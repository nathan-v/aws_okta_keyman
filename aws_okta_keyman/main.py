#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright 2018 Nextdoor.com, Inc
# Copyright 2018 Nathan V

from __future__ import unicode_literals
import getpass
import logging
import sys
import time
import requests
from builtins import input

import rainbow_logging_handler

from aws_okta_keyman import okta
from aws_okta_keyman import aws
from aws_okta_keyman.config import Config
from aws_okta_keyman.metadata import __desc__, __version__


def user_input(text):
    '''Wraps input() making testing support of py2 and py3 easier'''
    return input(text)


def setup_logging():
    '''Returns back a pretty color-coded logger'''
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = rainbow_logging_handler.RainbowLoggingHandler(sys.stdout)
    fmt = '%(asctime)-10s (%(levelname)s) %(message)s'
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def main(argv):
    # Generate our logger first, and write out our app name and version
    log = setup_logging()
    log.info('%s v%s' % (__desc__, __version__))

    # Get our configuration object based on the CLI options. This handles
    # parsing arguments and ensuring the user supplied the required params.
    config = Config(argv)
    try:
        config.get_config()
    except ValueError as err:
        log.fatal(err)
        sys.exit(1)

    if config.appid is None and config.accounts:
        msg = 'No app ID provided; please select from available AWS accounts'
        log.warning(msg)
        accts = config.accounts
        for acct_index, role in enumerate(accts):
            print("[{}] Account: {}".format(acct_index, role["name"]))
        acct_selection = int(user_input('Select an account from above: '))
        config.set_appid_from_account_id(acct_selection)
        msg = "Using account: {} / {}".format(accts[acct_selection]["name"],
                                              accts[acct_selection]["appid"])
        log.info(msg)

    if config.debug:
        log.setLevel(logging.DEBUG)

    # Ask the user for their password.. we do this once at the beginning, and
    # we keep it in memory for as long as this tool is running. Its never ever
    # written out or cached to disk anywhere.
    try:
        password = getpass.getpass()
    except KeyboardInterrupt:
        print('')
        sys.exit(1)

    # Generate our initial OktaSaml client and handle any exceptions thrown.
    # Generally these are input validation issues.
    try:
        if config.oktapreview is True:
            okta_client = okta.OktaSaml(config.org, config.username, password,
                                        oktapreview=True)
        else:
            okta_client = okta.OktaSaml(config.org, config.username, password)
    except okta.EmptyInput:
        log.fatal('Cannot enter a blank string for any input')
        sys.exit(1)

    # Authenticate the Okta client. If necessary, we will ask for MFA input.
    try:
        okta_client.auth()
    except okta.InvalidPassword:
        log.fatal('Invalid Username ({user}) or Password'.format(
            user=config.username))
        sys.exit(1)
    except okta.PasscodeRequired as e:
        log.warning('MFA Requirement Detected - Enter your passcode here')
        verified = False
        while not verified:
            passcode = user_input('MFA Passcode: ')
            verified = okta_client.validate_mfa(e.fid, e.state_token, passcode)
    except okta.UnknownError as err:
        log.fatal("Fatal error: {}".format(err))
        sys.exit(1)

    # Once we're authenticated with an OktaSaml client object, we can use that
    # object to get a fresh SAMLResponse repeatedly and refresh our AWS
    # Credentials.
    session = None
    role_selection = None
    retries = 0
    while True:
        # If an AWS Session object has been created already, lets check if its
        # still valid. If it is, sleep a bit and skip to the next execution of
        # the loop.
        if session and session.is_valid:
            log.debug('Credentials are still valid, sleeping')
            time.sleep(15)
            continue

        log.info('Getting SAML Assertion from {org}'.format(
            org=config.org))

        try:
            assertion = okta_client.get_assertion(appid=config.appid,
                                                  apptype='amazon_aws')
            session = aws.Session(assertion, profile=config.name)

            # If role_selection is set we're in a reup loop. Re-set the role on
            # the session to prevent the user being prompted for the role again
            # on each subsequent renewal.
            if role_selection is not None:
                session.set_role(role_selection)

            session.assume_role()

        except aws.MultipleRoles:
            log.warning('Multiple AWS roles found; please select one')
            roles = session.available_roles()
            for role_index, role in enumerate(roles):
                print("[{}] Role: {}".format(role_index, role["role"]))
            role_selection = user_input('Select a role from above: ')
            session.set_role(role_selection)
            session.assume_role()
        except requests.exceptions.ConnectionError as e:
            log.warning('Connection error... will retry')
            time.sleep(5)
            continue

        except aws.InvalidSaml:
            log.error('SAML response from AWS is invalid. Retrying...')
            time.sleep(1)
            retries += 1
            if retries > 2:
                log.fatal('SAML failure. Please reauthenticate.')
                sys.exit(1)

        # If we're not running in re-up mode, once we have the assertion
        # and creds, go ahead and quit.
        if not config.reup:
            break

        log.info('Reup enabled, sleeping...')
        time.sleep(5)


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    raise SystemExit(main(sys.argv))


if __name__ == '__main__':
    entry_point()
