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
# Copyright 2017 Nextdoor.com, Inc

import argparse
import getpass
import logging
import sys
import time

import rainbow_logging_handler

from nd_okta_auth import okta
from nd_okta_auth import aws
from nd_okta_auth.metadata import __desc__, __version__


def setup_logging():
    # Set up our pretty logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = rainbow_logging_handler.RainbowLoggingHandler(sys.stdout)
    fmt = '%(asctime)-10s (%(levelname)s) %(message)s'
    formatter = logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def main(argv):
    log = setup_logging()
    log.info('%s v%s' % (__desc__, __version__))

    arg_parser = argparse.ArgumentParser(
        prog=argv[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Okta Auther')

    arg_parser.add_argument('-V', '--version', action='version',
                            version=__version__)
    arg_parser.add_argument('-D', '--debug', action='store_true',
                            default=False)
    arg_parser.add_argument('-s', '--server', type=str, help='Okta server',
                            required=True)
    arg_parser.add_argument('-u', '--username', type=str, help='Username',
                            required=True)
    arg_parser.add_argument('-a', '--appid', type=str, help='Application ID',
                            required=True)
    arg_parser.add_argument('-r', '--reup', type=int,
                            help=(
                                'Automatically re-up the AWS creds every'
                                'xx seconds.'
                            ), default=0)

    config = arg_parser.parse_args(args=argv[1:])

    if config.debug:
        log.setLevel(logging.DEBUG)

    # Ask the user for their password.. we do this once at the beginning, and
    # we keep it in memory for as long as this tool is running. Its never ever
    # written out or cached to disk anywhere.
    password = getpass.getpass()

    # First things first, try to log in without MFA. If MFA is required, then
    # prompt.
    try:
        okta_client = okta.OktaSaml(config.server, config.username, password)
    except okta.EmptyInput:
        log.error('Cannot enter a blank string for any input')
        sys.exit(1)

    # Authenticate the Okta client. If necessary, we will ask for MFA input.
    try:
        okta_client.auth()
    except okta.InvalidPassword:
        log.error('Invalid Username or Password')
        sys.exit(1)
    except okta.PasscodeRequired as e:
        log.warning('MFA Requirement Detected - Enter your passcode here')
        verified = False
        while not verified:
            passcode = getpass.getpass('MFA Passcode: ')
            verified = okta_client.validate_mfa(e.fid, e.state_token, passcode)

    while True:
        log.info('Getting SAML Assertion from {server}'.format(
            server=config.server))
        assertion = okta_client.get_assertion(
            appid=config.appid, apptype='amazon_aws')

        creds = aws.Credentials(assertion)
        creds.assume_role_with_saml()

        if config.reup < 1:
            sys.exit(1)

        time.sleep(config.reup)


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    raise SystemExit(main(sys.argv))


if __name__ == '__main__':
    entry_point()
