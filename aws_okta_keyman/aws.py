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

from __future__ import unicode_literals
from builtins import str
import configparser
import datetime
import logging
import os
from os.path import expanduser
import xml

import boto3
from aws_okta_keyman.aws_saml import SamlAssertion

log = logging.getLogger(__name__)


class BaseException(Exception):
    '''Base AWS SAML Exception'''


class InvalidSaml(BaseException):
    '''Raised when the SAML Assertion is invalid for some reason'''


class MultipleRoles(BaseException):
    '''Raised when AWS offers multiple roles'''


class Credentials(object):

    '''Simple AWS Credentials Profile representation.

    This object reads in an Amazon ~/.aws/credentials file, and then allows you
    to write out credentials into different Profile sections.
    '''

    def __init__(self, filename):
        self.filename = filename

    def _add_profile(self, name, profile):
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read_file(open(self.filename, 'r'))
        except IOError:
            pass

        if not config.has_section(name):
            config.add_section(name)

        [(config.set(name, k, v)) for k, v in profile.items()]
        with open(self.filename, 'w+') as configfile:
            os.chmod(self.filename, 0o600)
            config.write(configfile)

    def add_profile(self, name, region, access_key, secret_key, session_token):
        '''Writes out a set of AWS Credentials to disk.

        args:
            name: The profile name to write to
            region: The region to use as the default region for this profile
            access_key: The AWS_ACCESS_KEY_ID
            secret_key: The AWS_SECRET_ACCESS_KEY
            session_token: The AWS_SESSION_TOKEN
        '''
        name = str(name)
        self._add_profile(
            name,
            {'output': 'json',
             'region': str(region),
             'aws_access_key_id': str(access_key),
             'aws_secret_access_key': str(secret_key),
             'aws_security_token': str(session_token),
             'aws_session_token': str(session_token)
             })

        log.info('Wrote profile "{name}" to {file}'.format(
            name=name, file=self.filename))


class Session(object):

    '''Amazon Federated Session Generator.

    This class is used to contact Amazon with a specific SAML Assertion and
    get back a set of temporary Federated credentials. These credentials are
    written to disk (using the Credentials object above).

    This object is meant to be used once -- as SAML Assertions are one-time-use
    objects.
    '''

    def __init__(self,
                 assertion,
                 credential_path='~/.aws',
                 profile='default',
                 region='us-east-1'):
        cred_dir = expanduser(credential_path)
        cred_file = os.path.join(cred_dir, 'credentials')

        boto_logger = logging.getLogger('botocore')
        boto_logger.setLevel(logging.WARNING)

        if not os.path.exists(cred_dir):
            log.info('Creating missing AWS Credentials dir {dir}'.format(
                dir=cred_dir))
            os.makedirs(cred_dir)

        self.sts = boto3.client('sts')

        self.profile = profile
        self.region = region

        self.assertion = SamlAssertion(assertion)
        self.writer = Credentials(cred_file)

        # Populated by self.assume_role()
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.aws_session_token = None
        self.expiration = None
        self.session_token = None
        self.role = None

    @property
    def is_valid(self):
        '''Returns True if the Session is still valid.

        Takes the current time (in UTC) and compares it to the Expiration time
        returned by Amazon. Adds a 10 minute buffer to make sure that we start
        working to renew the creds far before they really expire and break.

        Args:
            now: A datetime.datetime() object (likely
            datetime.datetime.utcnow())
            buffer: Number of seconds before the actual expiration before we
            start returning false.

        Returns:
            Bool
        '''
        # Consider the tokens expired when they have 10m left
        try:
            buffer = datetime.timedelta(seconds=600)
            now = datetime.datetime.utcnow()
            expir = datetime.datetime.strptime(str(self.expiration),
                                               '%Y-%m-%d %H:%M:%S+00:00')

            return (now + buffer) < expir
        except ValueError:
            return False

    def set_role(self, role_index):
        '''Sets the role based on the supplied index value'''
        self.role = self.assertion.roles()[int(role_index)]

    def available_roles(self):
        '''Returns the roles availble from AWS'''
        return self.assertion.roles()

    def assume_role(self):
        '''Use the SAML Assertion to actually get the credentials.

        Uses the supplied (one time use!) SAML Assertion to go out to Amazon
        and get back a set of temporary credentials. These are written out to
        disk and can be used for an hour before they need to be replaced.
        '''
        if self.role is None:
            try:
                if len(self.assertion.roles()) > 1:
                    raise MultipleRoles
                self.role = self.assertion.roles()[0]
            except xml.etree.ElementTree.ParseError:
                log.error('Could not find any Role in the SAML assertion')
                log.error(self.assertion.__dict__)
                raise InvalidSaml()

        log.info('Assuming role: {}'.format(self.role['role']))

        session = self.sts.assume_role_with_saml(
            RoleArn=self.role['role'],
            PrincipalArn=self.role['principle'],
            SAMLAssertion=self.assertion.encode())
        creds = session['Credentials']

        self.aws_access_key_id = creds['AccessKeyId']
        self.aws_secret_access_key = creds['SecretAccessKey']
        self.session_token = creds['SessionToken']
        self.expiration = creds['Expiration']

        self._write()

    def _write(self):
        '''Writes out our secrets to the Credentials object'''
        self.writer.add_profile(
            name=self.profile,
            region=self.region,
            access_key=self.aws_access_key_id,
            secret_key=self.aws_secret_access_key,
            session_token=self.session_token)
        log.info('Session expires at {time}'.format(
            time=self.expiration))
