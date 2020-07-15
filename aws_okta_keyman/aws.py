# -*- coding: utf-8 -*-
#
# Credits: Portions of this code were copied/modified from
# https://github.com/ThoughtWorksInc/aws_role_credentials
#
# Copyright (c) 2015, Peter Gillard-Moss
# All rights reserved.

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""
AWS Session and Credential classes; how we record the creds and how we talk
to AWS to get them.
"""
from __future__ import unicode_literals

import configparser
import datetime
import json
import logging
import os
import re
from builtins import str

import boto3
import botocore
import bs4
import requests

from aws_okta_keyman.aws_saml import SamlAssertion

LOG = logging.getLogger(__name__)


class BaseException(Exception):
    """Base AWS SAML Exception."""


class InvalidSaml(BaseException):
    """Raised when the SAML Assertion is invalid for some reason."""


class MultipleRoles(BaseException):
    """Raised when AWS offers multiple roles."""


class Credentials(object):
    """Simple AWS Credentials Profile representation.

    This object reads in an Amazon ~/.aws/credentials file, and then allows you
    to write out credentials into different Profile sections.
    """

    def __init__(self, filename):
        self.filename = filename

    def _add_profile(self, name, profile):
        """Do all the heavy lifting to write the profile out to disk."""
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read_file(open(self.filename, 'r'))
        except IOError:
            LOG.debug("Unable to open {}".format(self.filename))

        if not config.has_section(name):
            config.add_section(name)

        [(config.set(name, k, v)) for k, v in profile.items()]
        with open(self.filename, 'w+') as configfile:
            os.chmod(self.filename, 0o600)
            config.write(configfile)

    def add_profile(self, name, region, creds):
        """Write out a set of AWS Credentials to disk.

        args:
            name: The profile name to write to
            region: The region to use as the default region for this profile
            creds: AWS creds dict
        """
        name = str(name)
        self._add_profile(
            name,
            {'output': 'json',
             'region': str(region),
             'aws_access_key_id': str(creds['AccessKeyId']),
             'aws_secret_access_key': str(creds['SecretAccessKey']),
             'aws_security_token': str(creds['SessionToken']),
             'aws_session_token': str(creds['SessionToken'])})

        LOG.info('Wrote profile "{name}" to {file} 💾'.format(
            name=name, file=self.filename))


class Session(object):
    """Amazon Federated Session Generator.

    This class is used to contact Amazon with a specific SAML Assertion and
    get back a set of temporary Federated credentials. These credentials are
    written to disk (using the Credentials object above).

    This object is meant to be used once -- as SAML Assertions are one-time-use
    objects.
    """

    def __init__(self,
                 assertion,
                 credential_path='~/.aws',
                 profile='default',
                 region='us-east-1',
                 role=None,
                 session_duration=3600):
        cred_dir = os.path.expanduser(credential_path)
        cred_file = os.path.join(cred_dir, 'credentials')

        boto_logger = logging.getLogger('botocore')
        boto_logger.setLevel(logging.WARNING)

        if not os.path.exists(cred_dir):
            LOG.info('Creating missing AWS Credentials dir {dir} 📁'.format(
                dir=cred_dir))
            os.makedirs(cred_dir)

        self.profile = profile
        self.region = region
        boto3.setup_default_session(profile_name=profile)
        self.sts = boto3.client('sts', region_name=self.region)
        self.assertion = SamlAssertion(assertion)
        self.writer = Credentials(cred_file)

        # Populated by self.assume_role()
        self.creds = {
            'AccessKeyId': None,
            'SecretAccessKey': None,
            'SessionToken': None,
            'Expiration': None}
        self.session_token = None
        self.role = role
        self.duration = session_duration
        self.available_roles()

    @property
    def is_valid(self):
        """Return True if the Session is still valid.

        Returns:
            Bool
        """
        # Consider the tokens expired when they have 10m left
        try:
            msg = ("Session Expiration: {}  // Now: {}".format(
                self.creds['Expiration'],
                datetime.datetime.utcnow()))
            LOG.debug(msg)
            offset = datetime.timedelta(seconds=600)
            now = datetime.datetime.utcnow()
            expir = datetime.datetime.strptime(str(self.creds['Expiration']),
                                               '%Y-%m-%d %H:%M:%S+00:00')

            return (now + offset) < expir
        except (ValueError, TypeError):
            return False

    def available_roles(self):
        """Return the roles available from AWS.

        Returns: Tuple, list of roles as dicts and a bool that is true when
        multiple accounts were found
        """
        multiple_accounts = False
        first_account = ''
        formatted_roles = []
        for role in self.assertion.roles():
            account = role['role'].split(':')[4]
            role_name = role['role'].split(':')[5].split('/')[1]
            formatted_roles.append({
                'account': account,
                'role_name': role_name,
                'arn': role['role'],
                'principle': role['principle']
            })
            if first_account == '':
                first_account = account
            elif first_account != account:
                multiple_accounts = True

        if multiple_accounts:
            formatted_roles = self.account_ids_to_names(formatted_roles)

        formatted_roles = sorted(formatted_roles,
                                 key=lambda k: (k['account'], k['role_name']))

        # set the role role index after sorting
        i = 0
        for role in formatted_roles:
            role['roleIdx'] = i
            i = i + 1

        self.roles = formatted_roles

        return self.roles

    def assume_role(self, print_only=False):
        """Use the SAML Assertion to actually get the credentials.

        Uses the supplied (one time use!) SAML Assertion to go out to Amazon
        and get back a set of temporary credentials. These are written out to
        disk and can be used for an hour before they need to be replaced.
        """
        if self.role is None:
            if len(self.assertion.roles()) > 1:
                raise MultipleRoles
            self.role = 0

        LOG.info('Assuming role: {}'.format(self.roles[self.role]['arn']))

        try:
            session = self.sts.assume_role_with_saml(
                RoleArn=self.roles[self.role]['arn'],
                PrincipalArn=self.roles[self.role]['principle'],
                SAMLAssertion=self.assertion.encode(),
                DurationSeconds=self.duration)
        except botocore.exceptions.ClientError:
            # Try again with the default duration
            msg = ("Error assuming session with duration "
                   "{}. Retrying with 3600.".format(self.duration))
            LOG.warning(msg)
            session = self.sts.assume_role_with_saml(
                RoleArn=self.roles[self.role]['arn'],
                PrincipalArn=self.roles[self.role]['principle'],
                SAMLAssertion=self.assertion.encode(),
                DurationSeconds=3600)

        self.creds = session['Credentials']

        if print_only:
            self._print_creds()
        else:
            self._write()

    def _write(self):
        """Write out our secrets to the Credentials object."""
        self.writer.add_profile(
            name=self.profile,
            region=self.region,
            creds=self.creds)
        LOG.info('Current time is {time}'.format(
            time=datetime.datetime.utcnow()))
        LOG.info('Session expires at {time} ⏳'.format(
            time=self.creds['Expiration']))

    def _print_creds(self):
        """ Print out the retrieved credentials to the screen
        """
        cred_str = "AWS_ACCESS_KEY_ID = {}\n".format(self.creds['AccessKeyId'])
        cred_str = "{}AWS_SECRET_ACCESS_KEY = {}\n".format(
            cred_str, self.creds['SecretAccessKey'])
        cred_str = "{}AWS_SESSION_TOKEN = {}".format(
            cred_str, self.creds['SessionToken'])
        LOG.info("AWS Credentials: \n\n\n{}\n\n".format(cred_str))

    def generate_aws_console_url(self, issuer):
        """ Generate a URL for logging into the AWS console with the current
        session key

        Returns: string URL for console login
        """
        creds = {'sessionId': self.creds['AccessKeyId'],
                 'sessionKey': self.creds['SecretAccessKey'],
                 'sessionToken': self.creds['SessionToken']}

        params = {'Action': 'getSigninToken',
                  'SessionDuration': self.duration,
                  'Session': json.dumps(creds)}

        token_url = "https://signin.aws.amazon.com/federation"
        resp = requests.get(token_url, params=params)
        token = resp.json()['SigninToken']

        console_url = 'https%3A//console.aws.amazon.com/'
        params = ("?Action=login&Issuer={}&Destination={}"
                  "&SigninToken={}").format(issuer, console_url, token)

        url = "https://signin.aws.amazon.com/federation{}".format(params)
        return url

    def export_creds_to_var_string(self):
        """ Export the current credentials as environment vaiables
        """
        var_string = (
            "export AWS_ACCESS_KEY_ID={}; "
            "export AWS_SECRET_ACCESS_KEY={}; "
            "export AWS_SESSION_TOKEN={};"
        ).format(
            self.creds['AccessKeyId'],
            self.creds['SecretAccessKey'],
            self.creds['SessionToken']
        )
        return var_string

    def account_ids_to_names(self, roles):
        """Turn account IDs into user-friendly names

        args:
            roles: Dict of the roles from AWS to get the account names for

        Returns: Dict of account names and role names for user selection
        """
        try:
            accounts = self.get_account_name_map()
        except Exception:
            msg = ('Error retreiving AWS account name/ID map. '
                   'Falling back to just account IDs')
            LOG.warning(msg)
            return roles
        for role in roles:
            role['account'] = accounts[role['account']]
        LOG.debug("AWS roles with friendly names: {}".format(accounts))
        return roles

    def get_account_name_map(self):
        """ Get the friendly to ID mappings from AWS via hacktastic HTML

        Returns: Dict of account numbers with names
        """
        url = 'https://signin.aws.amazon.com/saml'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'SAMLResponse': self.assertion.encode()}
        resp = requests.post(url=url, headers=headers, data=data)
        resp.raise_for_status()
        return self.account_names_from_html(resp.text)

    @staticmethod
    def account_names_from_html(html):
        """ Parse the AWS SAML login page HTML for account numbers and names

        Returns: Dict of the account numbers and names
        """
        accounts = {}
        soup = bs4.BeautifulSoup(html, 'html.parser')
        for account in soup.find_all('div', {'class': 'saml-account-name'}):
            name_string = account.text
            a_id = re.match(r".*\((\d+)\)", name_string).group(1)
            a_name = re.match(r"\S+\s(\S+)", name_string).group(1)
            accounts[a_id] = a_name
        LOG.debug("AWS account map: {}".format(accounts))
        return accounts
