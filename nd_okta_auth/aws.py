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

from os.path import expanduser

from aws_role_credentials import models

log = logging.getLogger(__name__)


class Profile(object):

    def __init__(self, filename):
        self.filename = filename

    def _add_profile(self, name, profile):
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read_file(open(self.filename, 'r'))
        except:
            pass

        if not config.has_section(name):
            config.add_section(name)

        [(config.set(name, k, v)) for k, v in profile.items()]
        with open(self.filename, 'w+') as configfile:
            config.write(configfile)

    def add_profile(self, name, region, access_key, secret_key, session_token):
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


class Credentials(object):

    def __init__(self,
                 assertion,
                 credential_path='~/.aws',
                 profile='default',
                 region='us-east-1'):
        cred_dir = expanduser(credential_path)
        cred_file = os.path.join(cred_dir, 'credentials')

        if not os.path.exists(cred_dir):
            log.info('Creating missing AWS Credentials dir {dir}'.format(
                dir=cred_dir))
            os.makedirs(cred_dir)

        self.sts = boto3.client('sts')

        self.profile = profile
        self.region = region
        self.assertion = models.SamlAssertion(assertion)
        self.credentials = Profile(cred_file)

    def assume_role_with_saml(self):
        role = self.assertion.roles()[0]
        creds = self.sts.assume_role_with_saml(
            RoleArn=role['role'],
            PrincipalArn=role['principle'],
            SAMLAssertion=self.assertion.encode())
        self._write(creds['Credentials'])

    def _write(self, creds):
        self.credentials.add_profile(
            name=self.profile,
            region=self.region,
            access_key=creds['AccessKeyId'],
            secret_key=creds['SecretAccessKey'],
            session_token=creds['SessionToken'])
        log.info('Session expires at {time}'.format(
            time=creds['Expiration']))
