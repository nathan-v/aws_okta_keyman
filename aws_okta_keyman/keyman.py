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
"""This module contains the primary logic of the tool."""
from __future__ import unicode_literals

import getpass
import logging
import sys
import time
from builtins import input

import rainbow_logging_handler
import requests

from aws_okta_keyman import aws, okta, okta_saml
from aws_okta_keyman.config import Config
from aws_okta_keyman.metadata import __desc__, __version__


class Keyman:
    """Main class for the tool."""

    def __init__(self, argv):
        self.okta_client = None
        self.log = self.setup_logging()
        self.log.info('{} v{}'.format(__desc__, __version__))
        self.config = Config(argv)
        try:
            self.config.get_config()
        except ValueError as err:
            self.log.fatal(err)
            sys.exit(1)
        if self.config.debug:
            self.log.setLevel(logging.DEBUG)

    def main(self):
        """Execute primary logic path."""
        try:
            # If there's no appid try to select from accounts in config file
            self.handle_appid_selection()

            # get user password
            password = self.config.password
            if self.config.password == "":
                password = self.user_password()

            # Generate our initial OktaSaml client
            self.init_okta(password)

            # Authenticate to Okta
            self.auth_okta()

            # Start the AWS session and loop (if using reup)
            self.aws_auth_loop()

        except KeyboardInterrupt:
            # Allow users to exit cleanly at any time.
            print('')
            self.log.info('Exiting after keyboard interrupt.')
            sys.exit(1)

    @staticmethod
    def setup_logging():
        """Return back a pretty color-coded logger."""
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        handler = rainbow_logging_handler.RainbowLoggingHandler(sys.stdout)
        fmt = '%(asctime)-10s (%(levelname)s) %(message)s'
        formatter = logging.Formatter(fmt)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    @staticmethod
    def user_input(text):
        """Wrap input() making testing support of py2 and py3 easier."""
        return input(text)

    @staticmethod
    def user_password():
        """Wrap getpass to simplify testing."""
        return getpass.getpass()

    def selector_menu(self, options, key, key_name):
        """Show a selection menu from a dict so the user can pick something."""
        selection = -1
        while selection < 0 or selection > len(options):
            for index, option in enumerate(options):
                print("[{}] {}: {}".format(index, key_name, option[key]))
            selection = int(self.user_input("{} selection: ".format(key_name)))
        return selection

    def handle_appid_selection(self):
        """If we have no appid specified and we have accounts from a config
        file display the options to the user and select one
        """
        if self.config.appid is None and self.config.accounts:
            msg = 'No app ID provided; select from available AWS accounts'
            self.log.warning(msg)
            accts = self.config.accounts
            if self.config.appname:
                acct_selection = self.config.set_appid_from_account_name(
                    self.config.appname)
                print(acct_selection)
            else:
                acct_selection = self.selector_menu(accts, 'name', 'Account')
                self.config.set_appid_from_account_id(acct_selection)
            msg = "Using account: {} / {}".format(
                accts[acct_selection]["name"], accts[acct_selection]["appid"]
            )
            self.log.info(msg)

    def init_okta(self, password):
        """Initialize the Okta client or exit if the client received an empty
        input value
        """
        try:
            if self.config.oktapreview is True:
                self.okta_client = okta_saml.OktaSaml(self.config.org,
                                                      self.config.username,
                                                      password,
                                                      oktapreview=True)
            else:
                self.okta_client = okta_saml.OktaSaml(self.config.org,
                                                      self.config.username,
                                                      password)

        except okta.EmptyInput:
            self.log.fatal('Cannot enter a blank string for any input')
            sys.exit(1)

    def auth_okta(self):
        """Authenticate the Okta client. Prompt for MFA if necessary"""
        try:
            self.okta_client.auth()
        except okta.InvalidPassword:
            self.log.fatal('Invalid Username ({user}) or Password'.format(
                user=self.config.username
            ))
            sys.exit(1)
        except okta.PasscodeRequired as err:
            self.log.warning(
                "MFA Requirement Detected - Enter your {} code here".format(
                    err.provider
                )
            )
            verified = False
            while not verified:
                passcode = self.config.passcode
                if self.config.passcode == "":
                    passcode = self.user_input('MFA Passcode: ')
                verified = self.okta_client.validate_mfa(err.fid,
                                                         err.state_token,
                                                         passcode)
        except okta.AnswerRequired as err:
            self.log.warning('Question/Answer MFA response required.')
            self.log.warning("{}".format(
                err.factor['profile']['questionText'])
            )
            verified = False
            while not verified:
                answer = self.user_input('Answer: ')
                verified = self.okta_client.validate_answer(err.factor['id'],
                                                            err.state_token,
                                                            answer)
        except okta.UnknownError as err:
            self.log.fatal("Fatal error: {}".format(err))
            sys.exit(1)

    def handle_multiple_roles(self, session):
        """If there's more than one role available from AWS present the user
        with a list to pick from
        """
        self.log.warning('Multiple AWS roles found; please select one')
        roles = session.available_roles()
        role_selection = None
        if self.config.role:
            role_selection = self.config.get_role_index(roles)
        else:
            role_selection = self.selector_menu(roles, 'role', 'Role')
        session.set_role(role_selection)
        session.assume_role()
        return role_selection

    def start_session(self):
        """Initialize AWS session object."""
        try:
            assertion = self.okta_client.get_assertion(appid=self.config.appid,
                                                       apptype='amazon_aws')
        except okta.UnknownError:
            sys.exit(1)

        return aws.Session(assertion, profile=self.config.name)

    def aws_auth_loop(self):
        """Once we're authenticated with an OktaSaml client object we use that
        object to get a fresh SAMLResponse repeatedly and refresh our AWS
        Credentials.
        """
        session = None
        role_selection = None
        retries = 0
        while True:
            # If we have a session and it's valid take a nap
            if session and session.is_valid:
                self.log.debug('Credentials are still valid, sleeping')
                time.sleep(15)
                continue

            self.log.info('Getting SAML Assertion from {org}'.format(
                org=self.config.org))

            try:
                session = self.start_session()

                # If role_selection is set we're in a reup loop. Re-set the
                # role on the session to prevent the user being prompted for
                # the role again on each subsequent renewal.
                if role_selection is not None:
                    session.set_role(role_selection)

                session.assume_role()

            except aws.MultipleRoles:
                role_selection = self.handle_multiple_roles(session)
            except requests.exceptions.ConnectionError:
                self.log.warning('Connection error... will retry')
                time.sleep(5)
                continue
            except aws.InvalidSaml:
                self.log.error('AWS SAML response invalid. Retrying...')
                time.sleep(1)
                retries += 1
                if retries > 2:
                    self.log.fatal('SAML failure. Please reauthenticate.')
                    sys.exit(1)
                continue

            # If we're not running in re-up mode, once we have the assertion
            # and creds, go ahead and quit.
            if not self.config.reup:
                return

            self.log.info('Reup enabled, sleeping...')
            time.sleep(5)
