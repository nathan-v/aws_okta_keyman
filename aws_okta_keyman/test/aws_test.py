from __future__ import unicode_literals

import datetime
import sys
import unittest

from aws_okta_keyman import aws

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class TestCredentials(unittest.TestCase):

    @mock.patch('aws_okta_keyman.aws.os.chmod')
    @mock.patch('configparser.ConfigParser')
    @mock.patch('aws_okta_keyman.aws.open')
    def test_add_profile(self, open_mock, parser_mock, chmod_mock):
        fake_parser = mock.MagicMock(name='config_parser')
        parser_mock.return_value = fake_parser

        # Trigger the code to try to create a new section
        fake_parser.has_section.return_value = None

        profile = aws.Credentials('/test')
        profile.add_profile(
            name='TestProfile',
            region='us-east-1',
            creds={
                'AccessKeyId': 'key',
                'SecretAccessKey': 'secret',
                'SessionToken': 'token'})

        fake_parser.assert_has_calls([
            mock.call.has_section('TestProfile'),
            mock.call.add_section('TestProfile'),
            mock.call.set('TestProfile', 'region', 'us-east-1'),
            mock.call.set('TestProfile', 'aws_session_token', 'token'),
            mock.call.set('TestProfile', 'aws_security_token', 'token'),
            mock.call.set('TestProfile', 'aws_secret_access_key', 'secret'),
            mock.call.set('TestProfile', 'output', 'json'),
            mock.call.set('TestProfile', 'aws_access_key_id', 'key')
        ], any_order=True)

    @mock.patch('aws_okta_keyman.aws.os.chmod')
    @mock.patch('configparser.ConfigParser')
    @mock.patch('aws_okta_keyman.aws.open')
    def test_add_profile_missing_file_creates_new(self,
                                                  open_mock,
                                                  parser_mock,
                                                  chmod_mock):
        fake_parser = mock.MagicMock(name='config_parser')
        parser_mock.return_value = fake_parser

        # First time its called, throw an IOError to indicate the file doesnt
        # exist. Second time its called it returns a Mock for fake writing of
        # data.
        open_mock.side_effect = [IOError(), mock.MagicMock()]

        profile = aws.Credentials('/test')
        profile.add_profile(
            name='TestProfile',
            region='us-east-1',
            creds={
                'AccessKeyId': 'key',
                'SecretAccessKey': 'secret',
                'SessionToken': 'token'})

        open_mock.assert_has_calls([
            mock.call('/test', 'r'),
            mock.call('/test', 'w+')
        ])

        # Verify we're setting the file permissions as 0600 for safety
        chmod_mock.assert_has_calls([
            mock.call('/test', 0o600)
        ])


class TestSesssion(unittest.TestCase):

    @mock.patch('aws_okta_keyman.aws_saml.SamlAssertion')
    def setUp(self, mock_saml):
        self.fake_assertion = mock.MagicMock(name='FakeAssertion')
        mock_saml.return_value = self.fake_assertion

    def test_is_valid_false(self):
        session = aws.Session('BogusAssertion')

        # Mock out the expiration time to 4:10PM UTC
        expir_mock = datetime.datetime(2017, 7, 25, 16, 10, 00, 000000)
        # Now set our current time to 4:05PM UTC
        mock_now = datetime.datetime(2017, 7, 25, 16, 4, 00, 000000)

        # Should return False - less than 600 seconds away from expiration
        with mock.patch('datetime.datetime') as dt_mock:
            dt_mock.utcnow.return_value = mock_now
            dt_mock.strptime.return_value = expir_mock
            ret = session.is_valid

        self.assertEquals(False, ret)

    def test_is_valid_false_missing_expiration(self):
        session = aws.Session('BogusAssertion')

        # Set expiration to None like we failed to set the value
        session.expiration = None

        # Should return False - the time comparison isn't possible if
        # expiration hasn't been set yet.
        ret = session.is_valid

        self.assertEquals(False, ret)

    def test_is_valid_true(self):
        session = aws.Session('BogusAssertion')

        # Mock out the expiration time to 4:10PM UTC
        expir_mock = datetime.datetime(2017, 7, 25, 16, 10, 00, 000000)
        # Now set our current time to 3:55PM UTC
        mock_now = datetime.datetime(2017, 7, 25, 15, 55, 00, 000000)

        # Should return True - more than 600 seconds to expiration
        with mock.patch('datetime.datetime') as dt_mock:
            dt_mock.utcnow.return_value = mock_now
            dt_mock.strptime.return_value = expir_mock
            ret = session.is_valid

        self.assertEquals(True, ret)

    @mock.patch('aws_okta_keyman.aws.Credentials.add_profile')
    def test_write(self, mock_add_profile):
        session = aws.Session('BogusAssertion')
        ret = session._write()

        self.assertEquals(None, ret)

        # Verify add_profile is called with the correct args
        creds = {'AccessKeyId': None, 'SecretAccessKey': None,
                 'SessionToken': None, 'Expiration': None}
        mock_add_profile.assert_has_calls([
            mock.call(creds=creds, name='default', region='us-east-1')
        ])

    @mock.patch('aws_okta_keyman.aws.Session._write')
    def test_assume_role(self, mock_write):
        mock_write.return_value = None
        assertion = mock.Mock()
        assertion.roles.return_value = [{'role': '', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.assertion = assertion
        sts = {'Credentials':
               {'AccessKeyId':     'AKI',
                'SecretAccessKey': 'squirrel',
                'SessionToken':    'token',
                'Expiration':      'never'
                }}
        session.sts = mock.Mock()
        session.sts.assume_role_with_saml.return_value = sts
        ret = session.assume_role()

        self.assertEquals(None, ret)
        self.assertEquals('AKI', session.creds['AccessKeyId'])
        self.assertEquals('squirrel', session.creds['SecretAccessKey'])
        self.assertEquals('token', session.creds['SessionToken'])
        self.assertEquals('never', session.creds['Expiration'])

        # Verify _write is called correctly
        mock_write.assert_has_calls([
            mock.call()
        ])

    @mock.patch('aws_okta_keyman.aws.Session._write')
    def test_assume_role_multiple(self, mock_write):
        mock_write.return_value = None
        assertion = mock.Mock()
        roles = [{'role': '1', 'principle': ''},
                 {'role': '2', 'principle': ''}]
        assertion.roles.return_value = roles
        session = aws.Session('BogusAssertion')
        session.assertion = assertion
        sts = {'Credentials':
               {'AccessKeyId':     'AKI',
                'SecretAccessKey': 'squirrel',
                'SessionToken':    'token',
                'Expiration':      'never'
                }}
        session.sts = mock.Mock()
        session.sts.assume_role_with_saml.return_value = sts

        with self.assertRaises(aws.MultipleRoles):
            session.assume_role()

    def test_assume_role_bad_assertion_raises_invalidsaml(self):
        session = aws.Session('BogusAssertion')
        with self.assertRaises(aws.InvalidSaml):
            session.assume_role()

    def test_set_role(self):
        assertion = mock.Mock()
        assertion.roles.return_value = [{'role': '', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.assertion = assertion
        session.set_role('0')
        self.assertEquals('', session.role['role'])

    def test_available_roles(self):
        assertion = mock.Mock()
        roles = [{'role': '1', 'principle': ''},
                 {'role': '2', 'principle': ''}]
        assertion.roles.return_value = roles
        session = aws.Session('BogusAssertion')
        session.assertion = assertion
        result = session.available_roles()
        self.assertEquals(roles, result)
