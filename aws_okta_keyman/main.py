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
import argparse
import getpass
import logging
import sys
import time
import requests
from builtins import input

import rainbow_logging_handler

from aws_okta_keyman import okta
from aws_okta_keyman import aws
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


def get_config_parser(argv):
    '''Returns a configured ArgumentParser for the CLI options'''
    epilog = (
        '**Application ID**\n'
        'The ApplicationID is actually a two part piece of the redirect URL \n'
        'that Okta uses when you are logged into the Web UI. If you mouse \n'
        'over the appropriate Application and see a URL that looks like \n'
        'this. \n'
        '\n'
        '\thttps://foobar.okta.com/home/amazon_aws/0oaciCSo1d8/123?...\n'
        '\n'
        'You would enter in "0oaciCSo1d8/123" as your Application ID.\n')

    arg_parser = argparse.ArgumentParser(
        prog=argv[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
        description='Okta Auther')

    # Get rid of the default optional arguments section that always shows up.
    # Its not necessary, and confusing to have optional arguments listed first.
    #   https://stackoverflow.com/questions/24180527/
    #   argparse-required-arguments-listed-under-optional-arguments
    arg_parser._action_groups.pop()

    required_args = arg_parser.add_argument_group('required arguments')
    required_args.add_argument('-o', '--org', type=str,
                               help=(
                                   'Okta Organization Name - ie, if your login'
                                   ' URL is https://foobar.okta.com, enter in '
                                   'foobar here'
                               ),
                               required=True)
    required_args.add_argument('-u', '--username', type=str,
                               help=(
                                   'Okta Login Name - either bob@foobar.com, '
                                   'or just bob works too, depending on your '
                                   'organization settings.'
                               ),
                               required=True)
    required_args.add_argument('-a', '--appid', type=str,
                               help=(
                                   'The "redirect link" Application ID  - '
                                   'this can be found by mousing over the '
                                   'application in Okta\'s Web UI. See '
                                   'details below for more help.'
                               ),
                               required=True)

    optional_args = arg_parser.add_argument_group('optional arguments')
    optional_args.add_argument('-V', '--version', action='version',
                               version=__version__)
    optional_args.add_argument('-D', '--debug', action='store_true',
                               help=(
                                   'Enable DEBUG logging - note, this is '
                                   'extremely verbose and exposes credentials '
                                   'so be careful here!'
                               ),
                               default=False)
    optional_args.add_argument('-r', '--reup', action='store_true',
                               help=(
                                   'Automatically re-up the AWS creds before'
                                   'they expire.'
                               ), default=0)
    optional_args.add_argument('-n', '--name', type=str,
                               help='AWS Profile Name', default='default')

    config = arg_parser.parse_args(args=argv[1:])
    return config


def main(argv):
    # Generate our logger first, and write out our app name and version
    log = setup_logging()
    log.info('%s v%s' % (__desc__, __version__))

    # Get our configuration object based on the CLI options. This handles
    # parsing arguments and ensuring the user supplied the required params.
    config = get_config_parser(argv)

    if config.debug:
        log.setLevel(logging.DEBUG)

    # Ask the user for their password.. we do this once at the beginning, and
    # we keep it in memory for as long as this tool is running. Its never ever
    # written out or cached to disk anywhere.
    password = getpass.getpass()

    # Generate our initial OktaSaml client and handle any exceptions thrown.
    # Generally these are input validation issues.
    try:
        okta_client = okta.OktaSaml(config.org, config.username, password)
    except okta.EmptyInput:
        log.error('Cannot enter a blank string for any input')
        sys.exit(1)

    # Authenticate the Okta client. If necessary, we will ask for MFA input.
    try:
        okta_client.auth()
    except okta.InvalidPassword:
        log.error('Invalid Username ({user}) or Password'.format(
            user=config.username))
        sys.exit(1)
    except okta.PasscodeRequired as e:
        log.warning('MFA Requirement Detected - Enter your passcode here')
        verified = False
        while not verified:
            passcode = user_input('MFA Passcode: ')
            verified = okta_client.validate_mfa(e.fid, e.state_token, passcode)
    except okta.UnknownError as e:
        log.fatal('Fatal error.')
        sys.exit(1)

    # Once we're authenticated with an OktaSaml client object, we can use that
    # object to get a fresh SAMLResponse repeatedly and refresh our AWS
    # Credentials.
    session = None
    role_selection = None
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
