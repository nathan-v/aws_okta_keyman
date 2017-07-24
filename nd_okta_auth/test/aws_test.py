import unittest
import mock

from nd_okta_auth import aws


class TestCredentials(unittest.TestCase):

    @mock.patch('configparser.ConfigParser')
    @mock.patch('nd_okta_auth.aws.open')
    def test_add_profile(self, open_mock, parser_mock):
        fake_parser = mock.MagicMock(name='config_parser')
        parser_mock.return_value = fake_parser

        # Trigger the code to try to create a new section
        fake_parser.has_section.return_value = None

        profile = aws.Credentials('/test')
        profile.add_profile(
            name='TestProfile',
            region='us-east-1',
            access_key='key',
            secret_key='secret',
            session_token='token')

        fake_parser.assert_has_calls([
            mock.call.has_section(u'TestProfile'),
            mock.call.add_section(u'TestProfile'),
            mock.call.set(u'TestProfile', u'region', u'us-east-1'),
            mock.call.set(u'TestProfile', u'aws_session_token', u'token'),
            mock.call.set(u'TestProfile', u'aws_security_token', u'token'),
            mock.call.set(u'TestProfile', u'aws_secret_access_key', u'secret'),
            mock.call.set(u'TestProfile', u'output', u'json'),
            mock.call.set(u'TestProfile', u'aws_access_key_id', u'key')
        ])

    @mock.patch('configparser.ConfigParser')
    @mock.patch('nd_okta_auth.aws.open')
    def test_add_profile_missing_file_creates_new(self,
                                                  open_mock,
                                                  parser_mock):
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
            access_key='key',
            secret_key='secret',
            session_token='token')

        open_mock.assert_has_calls([
            mock.call('/test', 'r'),
            mock.call('/test', 'w+')
        ])
