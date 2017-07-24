'''
aws
^^^

Simple module for writing generating and writing out AWS Credentials into your
~/.aws/credentials file with a supplied Saml assertion.

Credits: This code base was almost entirely stolen from
https://github.com/ThoughtWorksInc/aws_role_credentials. It continues to be
modified from the original code, but thanks a ton to the original writers at
Thought Works Inc.
'''

import boto3
import configparser
import logging
import os
import xml

from os.path import expanduser

from aws_role_credentials import models

log = logging.getLogger(__name__)


class BaseException(Exception):
    '''Base AWS SAML Exception'''


class InvalidSaml(BaseException):
    '''Raised when the SAML Assertion is invalid for some reason'''


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
        name = unicode(name)
        self._add_profile(
            name,
            {u'output': u'json',
             u'region': unicode(region),
             u'aws_access_key_id': unicode(access_key),
             u'aws_secret_access_key': unicode(secret_key),
             u'aws_security_token': unicode(session_token),
             u'aws_session_token': unicode(session_token)
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
        self.assertion = models.SamlAssertion(assertion)
        self.credentials = Credentials(cred_file)

    def assume_role(self):
        '''Use the SAML Assertion to actually get the credentials.

        Uses the supplied (one time use!) SAML Assertion to go out to Amazon
        and get back a set of temporary credentials. These are written out to
        disk and can be used for an hour before they need to be replaced.
        '''
        try:
            role = self.assertion.roles()[0]
        except xml.etree.ElementTree.ParseError:
            log.error('Could not find any Role in the SAML assertion')
            log.error(self.assertion.__dict__)
            raise InvalidSaml()

        creds = self.sts.assume_role_with_saml(
            RoleArn=role['role'],
            PrincipalArn=role['principle'],
            SAMLAssertion=self.assertion.encode())
        self._write(creds['Credentials'])

    def _write(self, creds):
        '''Take in supplied credentials and write them to disk.

        Creds:
            A dictionary of values returned to us by Boto - should have
            AccessKeyId, SecretAccessKey and SessionToken keys.
        '''
        self.credentials.add_profile(
            name=self.profile,
            region=self.region,
            access_key=creds['AccessKeyId'],
            secret_key=creds['SecretAccessKey'],
            session_token=creds['SessionToken'])
        log.info('Session expires at {time}'.format(
            time=creds['Expiration']))
