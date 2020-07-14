#!/usr/bin/env python
# -*- coding: UTF-8 -*-

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
import os
import platform
import subprocess
import sys
import time
import traceback
import xml
from builtins import input

import botocore
import keyring
import requests

from aws_okta_keyman import aws, okta, okta_saml
from aws_okta_keyman.config import Config
from aws_okta_keyman.metadata import __desc__, __version__
from aws_okta_keyman.duo import PasscodeRequired, FactorRequired


LOG = logging.getLogger(__name__)


class NoAWSAccounts(Exception):
    """Some Expected Return Was Received."""


class Keyman:
    """Main class for the tool."""

    def __init__(self, argv):
        self.okta_client = None
        self.log = LOG
        self.log.info('{} 🔐 v{}'.format(__desc__, __version__))
        self.config = Config(argv)
        self.role = None
        try:
            self.config.get_config()
        except ValueError as err:
            self.log.fatal(err)
            sys.exit(1)
        if self.config.debug:
            self.log.setLevel(logging.DEBUG)

    def main(self):
        """Execute primary logic path."""
        if self.config.update is True:
            self.update(__version__)
            sys.exit(0)
        try:
            # If there's no appid try to select from accounts in config file
            self.handle_appid_selection()

            # get user password
            password = self.user_password()

            # Generate our initial OktaSaml client
            self.init_okta(password)

            # If still no appid get a list from Okta and have user pick
            if self.config.appid is None:
                # Authenticate to Okta
                self.auth_okta()
                self.handle_appid_selection(okta_ready=True)
            else:
                # Authenticate to Okta
                self.auth_okta()

            # Start the AWS session and loop (if using reup)
            result = self.aws_auth_loop()
            if result is not None:
                sys.exit(result)

        except NoAWSAccounts:
            self.log.fatal('No configured or assigned AWS apps found 🛑')
            sys.exit(6)

        except KeyboardInterrupt:
            # Allow users to exit cleanly at any time.
            print('')
            self.log.info('Exiting after keyboard interrupt. 🛑')
            sys.exit(1)

        except Exception as err:
            msg = '😬 Unhandled exception: {}'.format(err)
            self.log.fatal(msg)
            self.log.debug(traceback.format_exc())
            sys.exit(5)

    @staticmethod
    def user_input(text):
        """Wrap input() making testing support of py2 and py3 easier."""
        return input(text).strip()

    def user_password(self):
        """Wrap getpass to simplify testing."""
        password = None
        if self.config.password_cache:
            self.log.debug('Password cache enabled')
            try:
                keyring.get_keyring()
                password = keyring.get_password('aws_okta_keyman',
                                                self.config.username)
            except keyring.errors.InitError:
                msg = 'Password cache enabled but no keyring available.'
                self.log.warning(msg)
                password = getpass.getpass()

            if self.config.password_reset or password is None:
                self.log.debug('Password not in cache or reset requested')
                password = getpass.getpass()
                keyring.set_password('aws_okta_keyman', self.config.username,
                                     password)
        else:
            password = getpass.getpass()
        return password

    @staticmethod
    def generate_template(data, header_map):
        """ Generates a string template for printing a table using the data and
        header to define the column names and widths

        Args:
        data: List of dicts; the data that will go in the table
        header_map: List of dicts with the header name to key map

        Returns: String template used for printing a padded table
        """
        widths = []
        for col in header_map:
            col_key = list(col.keys())[0]
            values = [row[col_key] for row in data]
            col_wid = max(len(value) + 2 for value in values)
            if len(col[col_key]) + 2 > col_wid:
                col_wid = len(col[col_key]) + 2
            widths.append([col_key, col_wid])
        template = ''
        for col in widths:
            if template == '':
                template = "{}{}:{}{}".format('{', col[0], col[1], '}')
            else:
                template = "{}{}{}:{}{}".format(template,
                                                '{', col[0], col[1], '}')
        return template

    @staticmethod
    def generate_header(header_map):
        """ Generates a table header

        Args:
        header_map: List of dicts with the header name to key map

        Returns: Dict mapping data keys to column headers
        """
        header_dict = {}
        for col in header_map:
            header_dict.update(col)
        return header_dict

    @staticmethod
    def print_selector_table(template, header_map, data):
        """ Prints out a formatted table of data with headers and index
        numbers so that the user can be prompted to select a row as their
        response.

        Args:
        template: String template used to print each row
        header_map: List of dicts containing the data key to column title map
        data: List of dicts where each dict is a row in the table
        """
        selector_width = len(str(len(data) - 1)) + 2
        pad = " " * (selector_width + 1)
        header_dict = Keyman.generate_header(header_map)
        print("\n{}{}".format(pad, template.format(**header_dict)))
        for index, item in enumerate(data):
            sel = "[{}]".format(index).ljust(selector_width)
            print("{} {}".format(sel, str(template.format(**item))))

    def update(self, this_version):
        self.log.info('Checking AWS Okta Keyman current version on Pypi')
        pip_version = self.get_pip_version()
        if pip_version > this_version:
            self.log.info("New version {}. Updaing..".format(pip_version))
            os = platform.system()
            if os == "Darwin":
                result = subprocess.check_call([
                    'brew', 'upgrade', 'aws_okta_keyman'
                ])
            else:
                result = subprocess.check_call([
                    sys.executable, "-m", "pip", "install",
                    '--upgrade', 'aws-okta-keyman'
                ])
            if result == 0:
                self.log.info('AWS Okta Keyman updated.')
            else:
                msg = 'Error updating Keyman. Please try updating manually.'
                self.log.warning(msg)
        else:
            self.log.info('Keyman is up to date')

    @staticmethod
    def get_pip_version():
        url = 'https://pypi.org/pypi/aws-okta-keyman/json'
        resp = requests.get(url).json()
        pip_version = resp['info']['version']
        return pip_version

    def selector_menu(self, data, header_map):
        """ Presents a menu/table to the user from which they can make a
        selection using the index number of their choice

        Args:
        data: List of dicts where each dict is a row in the table
        header_map: List of dicts containing the data key to column title map

        Returns: Int as the index value for the row the user chose
        """
        template = self.generate_template(data, header_map)
        selection = -1
        while selection < 0 or selection > len(data):
            self.print_selector_table(template, header_map, data)
            try:
                selection = int(self.user_input("Selection: "))
            except ValueError:
                self.log.warning('Invalid selection, please try again')
                continue
        print('')
        return selection

    def handle_appid_selection(self, okta_ready=False):
        """If we have no appid specified and we have accounts from a config
        file display the options to the user and select one
        """
        if self.config.appid is None:
            if self.config.accounts:
                accts = self.config.accounts
            elif okta_ready:
                self.config.accounts = self.okta_client.get_aws_apps()
                accts = self.config.accounts
            else:
                return

            if len(accts) < 1:
                raise NoAWSAccounts()

            acct_selection = 0
            if len(accts) > 1:
                msg = 'No app ID provided; select from available AWS accounts'
                self.log.warning(msg)
                header = [{'name': 'Account'}]
                acct_selection = self.selector_menu(accts, header)
            self.config.set_appid_from_account_id(acct_selection)
            msg = "Using account: {} / {}".format(
                accts[acct_selection]["name"], accts[acct_selection]["appid"]
            )
            self.log.info(msg)

    def handle_duo_factor_selection(self):
        """If we have no Duo factor but are using Duo MFA the user needs to
        select a preferred factor so we can move ahead with Duo
        """
        msg = 'No Duo Auth factor specified; please select one:'
        self.log.warning(msg)

        factors = [{'name': '📲 Duo Push', 'factor': 'push'},
                   {'name': '📟 OTP Passcode', 'factor': 'passcode'},
                   {'name': '📞 Phone call', 'factor': 'call'}]
        header = [{'name': 'Duo Factor'}]
        duo_factor_index = self.selector_menu(factors, header)
        msg = "Using factor: {}".format(factors[duo_factor_index]["name"])
        self.log.info(msg)
        return factors[duo_factor_index]['factor']

    def init_okta(self, password):
        """Initialize the Okta client or exit if the client received an empty
        input value
        """
        try:
            if self.config.oktapreview is True:
                self.okta_client = okta_saml.OktaSaml(self.config.org,
                                                      self.config.username,
                                                      password,
                                                      self.config.duo_factor,
                                                      oktapreview=True)
            else:
                duo_factor = self.config.duo_factor
                self.okta_client = okta_saml.OktaSaml(self.config.org,
                                                      self.config.username,
                                                      password,
                                                      duo_factor=duo_factor)

        except okta.EmptyInput:
            self.log.fatal('Cannot enter a blank string for any input')
            sys.exit(1)

    def auth_okta(self, state_token=None):
        """Authenticate the Okta client. Prompt for MFA if necessary"""
        self.log.debug('Attempting to authenticate to Okta')
        try:
            self.okta_client.auth(state_token)
        except okta.InvalidPassword:
            self.log.fatal('Invalid Username ({user}) or Password'.format(
                user=self.config.username
            ))
            if self.config.password_cache:
                msg = (
                    'Password cache is in use; use option -R to reset the '
                    'cached password with a new value'
                )
                self.log.warning(msg)
            sys.exit(1)
        except okta.PasscodeRequired as err:
            self.log.warning(
                "MFA Requirement Detected - Enter your {} code here".format(
                    err.provider
                )
            )
            verified = False
            while not verified:
                passcode = self.user_input('MFA Passcode: ')
                verified = self.okta_client.validate_mfa(err.fid,
                                                         err.state_token,
                                                         passcode)
        except okta.AnswerRequired as err:
            self.log.warning('Question/Answer MFA response required.')
            self.log.warning("{}".format(
                err.factor['profile']['questionText']))
            verified = False
            while not verified:
                answer = self.user_input('Answer: ')
                verified = self.okta_client.validate_answer(err.factor['id'],
                                                            err.state_token,
                                                            answer)
        except FactorRequired:
            factor = self.handle_duo_factor_selection()
            self.okta_client.duo_factor = factor
            self.auth_okta()
        except PasscodeRequired as err:
            self.log.warning("OTP Requirement Detected - Enter your code here")
            verified = False
            while not verified:
                passcode = self.user_input('MFA Passcode: ')
                verified = self.okta_client.duo_auth(err.factor,
                                                     err.state_token,
                                                     passcode)
        except okta.UnknownError as err:
            self.log.fatal("Fatal error: {}".format(err))
            sys.exit(1)

    def handle_multiple_roles(self, session):
        """If there's more than one role available from AWS present the user
        with a list to pick from
        """

        roles = session.available_roles()

        if self.config.account or self.config.role:
            roles = list(filter(lambda item: (
                    (
                        not self.config.account
                        or item['account'] == self.config.account
                    )
                    and
                    (
                        not self.config.role
                        or item['role_name'] == self.config.role
                    )
                ),
                session.available_roles()
            ))

        if len(roles) == 0:
            # if filtering returned nothing fail
            self.log.fatal('Unable to find a matching account or role')
            return False
        elif len(roles) == 1:
            # if filtering returned a single item,
            # do not prompt for selection
            self.role = roles[0]['roleIdx']
        else:
            self.log.warning('Multiple AWS roles found; please select one')
            header = [{'account': 'Account'}, {'role_name': 'Role'}]
            role_idx = self.selector_menu(roles, header)
            self.role = roles[role_idx]['roleIdx']

        session.role = self.role
        return True

    def start_session(self):
        """Initialize AWS session object."""
        self.log.info('Getting SAML Assertion from {org}'.format(
            org=self.config.org))
        assertion = self.okta_client.get_assertion(
            appid=self.config.appid)

        try:
            self.log.info("Starting AWS session for {}".format(
                self.config.region))
            session = aws.Session(assertion, profile=self.config.name,
                                  role=self.role, region=self.config.region,
                                  session_duration=self.config.duration)

        except xml.etree.ElementTree.ParseError:
            self.log.error('Could not find any Role in the SAML assertion')
            self.log.error(assertion.__dict__)
            raise aws.InvalidSaml()
        return session

    def aws_auth_loop(self):
        """Once we're authenticated with an OktaSaml client object we use that
        object to get a fresh SAMLResponse repeatedly and refresh our AWS
        Credentials.
        """
        session = None
        retries = 0
        while True:
            # If we have a session and it's valid take a nap
            if session and session.is_valid:
                self.log.debug('Credentials are still valid, sleeping')
                time.sleep(60)
                retries = 0
                continue

            try:
                session = self.start_session()

                if not self.handle_multiple_roles(session):
                    return 1

                session.assume_role(self.config.screen)

            except requests.exceptions.ConnectionError:
                self.log.warning('Connection error... will retry')
                time.sleep(5)
                retries += 1
                if retries > 5:
                    self.log.fatal('Too many connection errors')
                    return 3
                continue  # pragma: no cover
            except (okta.UnknownError, aws.InvalidSaml):
                self.log.error('API response invalid. Retrying...')
                time.sleep(1)
                retries += 1
                if retries > 2:
                    self.log.fatal('SAML failure. Please reauthenticate.')
                    return 1
                continue  # pragma: no cover
            except okta.ReauthNeeded as err:
                msg = 'Application-level MFA present; re-authenticating Okta'
                self.log.warning(msg)
                self.auth_okta(state_token=err.state_token)
                continue
            except botocore.exceptions.ProfileNotFound as err:
                msg = (
                    'There is likely an issue with your AWS_DEFAULT_PROFILE '
                    'environment variable. An error occurred attempting to '
                    'load the AWS profile specified. '
                    'Error message: {}').format(err)
                self.log.fatal(msg)
                return 4

            if not self.config.reup:
                return self.wrap_up(session)

            self.log.info('Reup enabled, sleeping... 💤')

    def wrap_up(self, session):
        """ Execute any final steps when we're not in reup mode

        Args:
        session: aws.session object
        """
        if self.config.command:
            command_string = "{} {}".format(
                session.export_creds_to_var_string(),
                self.config.command
            )
            self.log.info("Running requested command...\n\n")
            os.system(command_string)
        elif self.config.console:
            app_url = self.config.full_app_url()
            url = session.generate_aws_console_url(app_url)
            self.log.info("AWS Console URL: {}".format(url))

        else:
            self.log.info('All done! 👍')
