from __future__ import unicode_literals

import datetime
import sys
import unittest

import botocore

from aws_okta_keyman import aws

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


AWS_HTML_MULTIACCOUNT_LOGIN = (
    '<!DOCTYPE html><html><head><title>Amazon Web Services Sign-In</title>'
    '</head><body><div id="container"><h1 class="background">'
    'Amazon Web Services Login</h1><div id="content"><form id="saml_form" '
    'name="saml_form" action="/saml" method="post"><input type="hidden" '
    'name="RelayState" value="" /><input type="hidden" name="name" value="" />'
    '<input type="hidden" name="portal" value="" /><fieldset><div class'
    '="saml-account"><div onClick="expandCollapse(0);"><img id="image0" src='
    '"/static/image/down.png" valign="middle"></img><div class="'
    'saml-account-name">Account: my-dev (123456)</div></div></div><hr style="'
    'border: 1px solid #ddd;"><div id="0" class="saml-account" ><div class="'
    'saml-role" onClick="checkRadio(this);"><input type="radio" name="'
    'roleIndex" value="arn:aws:iam::123456:role/admin" class="saml-radio" id="'
    'arn:aws:iam::123456:role/admin" /><label for="arn:aws:iam::123456:role/'
    'admin" class="saml-role-description">admin</label><span style="clear: '
    'both;"></span></div></div><div class="saml-account"><div onClick="'
    'expandCollapse(1);"><img id="image1" src="/static/image/down.png" '
    'valign="middle"></img><div class="saml-account-name">Account: my-prod '
    '(123457)</div></div></div><hr style="border: 1px solid #ddd;"><div id="1"'
    ' class="saml-account" ><div class="saml-role" onClick="checkRadio(this);"'
    '><input type="radio" name="roleIndex" value="arn:aws:iam::123457:role/'
    'admin" class="saml-radio" id="arn:aws:iam::123457:role/admin" /><label '
    'for="arn:aws:iam::123457:role/admin" class="saml-role-description">admin'
    '</label><span style="clear: both;"></span></div></div></fieldset></form>'
    '</div></div></body></html>')


class MockResponse:
    def __init__(self, text, exception=False):
        self.text = text
        self.exception = exception

    def raise_for_status(self):
        if self.exception:
            raise Exception()


class TestCredentials(unittest.TestCase):

    @mock.patch('aws_okta_keyman.aws.os.chmod')
    @mock.patch('aws_okta_keyman.aws.open')
    @mock.patch('configparser.ConfigParser')
    def test_add_profile(self, parser_mock, _open_mock, _chmod_mock):
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


class TestSession(unittest.TestCase):

    def setUp(self):
        self.patcher = mock.patch('aws_okta_keyman.aws.SamlAssertion')
        self.mock_saml = self.patcher.start()
        self.fake_assertion = mock.MagicMock(name='FakeAssertion')
        self.mock_saml.return_value = self.fake_assertion
        self.botopatch = mock.patch('aws_okta_keyman.aws.boto3')
        self.mock_boto = self.botopatch.start()

    @mock.patch('os.path.expanduser')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists')
    def test_init_folder_missing(self, exists_mock, makedirs_mock,
                                 expuser_mock):
        exists_mock.return_value = False
        expuser_mock.return_value = '/home/fakeuser'

        aws.Session('BogusAssertion')

        makedirs_mock.assert_has_calls([mock.call('/home/fakeuser')])

    @mock.patch('os.path.expanduser')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists')
    def test_init_folder_exists(self, exists_mock, _makedirs_mock,
                                expuser_mock):
        exists_mock.return_value = True
        expuser_mock.return_value = '/home/fakeuser'

        aws.Session('BogusAssertion')

        exists_mock.assert_has_calls([mock.call('/home/fakeuser')])

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

        self.assertEqual(False, ret)

    def test_is_valid_false_missing_expiration(self):
        session = aws.Session('BogusAssertion')

        # Set expiration to None like we failed to set the value
        session.expiration = None

        # Should return False - the time comparison isn't possible if
        # expiration hasn't been set yet.
        ret = session.is_valid

        self.assertEqual(False, ret)

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

        self.assertEqual(True, ret)

    @mock.patch('aws_okta_keyman.aws.Credentials.add_profile')
    def test_write(self, mock_add_profile):
        session = aws.Session('BogusAssertion')
        ret = session._write()

        self.assertEqual(None, ret)

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
        assertion.roles.return_value = [{'arn': '', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.roles = [{'arn': '', 'principle': ''}]
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

        self.assertEqual(None, ret)
        self.assertEqual('AKI', session.creds['AccessKeyId'])
        self.assertEqual('squirrel', session.creds['SecretAccessKey'])
        self.assertEqual('token', session.creds['SessionToken'])
        self.assertEqual('never', session.creds['Expiration'])
        # Verify _write is called correctly
        mock_write.assert_has_calls([
            mock.call()
        ])
        session.sts.assert_has_calls([
            mock.call.assume_role_with_saml(
                RoleArn='',
                PrincipalArn='',
                SAMLAssertion=mock.ANY,
                DurationSeconds=3600)
        ])

    @mock.patch('aws_okta_keyman.aws.Session._write')
    def test_assume_role_multiple(self, mock_write):
        mock_write.return_value = None
        assertion = mock.Mock()
        roles = [{'arn': '1', 'principle': ''},
                 {'arn': '2', 'principle': ''}]
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

    @mock.patch('aws_okta_keyman.aws.Session._write')
    def test_assume_role_preset(self, mock_write):
        mock_write.return_value = None
        assertion = mock.Mock()

        roles = [{'role': '::::1:role/role1', 'principle': '', 'arn': '1'},
                 {'role': '::::1:role/role2', 'principle': '', 'arn': '2'},
                 {'role': '::::1:role/role3', 'principle': '', 'arn': '3'}]

        assertion.roles.return_value = roles
        session = aws.Session('BogusAssertion')
        session.role = 1
        session.roles = roles
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

        self.assertEqual(None, ret)
        self.assertEqual('AKI', session.creds['AccessKeyId'])
        self.assertEqual('squirrel', session.creds['SecretAccessKey'])
        self.assertEqual('token', session.creds['SessionToken'])
        self.assertEqual('never', session.creds['Expiration'])
        # Verify _write is called correctly
        mock_write.assert_has_calls([
            mock.call()
        ])
        session.sts.assert_has_calls([
            mock.call.assume_role_with_saml(
                RoleArn='2',
                PrincipalArn='',
                SAMLAssertion=mock.ANY,
                DurationSeconds=3600)
        ])

    @mock.patch('aws_okta_keyman.aws.Session._print_creds')
    @mock.patch('aws_okta_keyman.aws.Session._write')
    def test_assume_role_print(self, mock_write, mock_print):
        assertion = mock.Mock()
        assertion.roles.return_value = [{'arn': '', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.role = 0
        session.roles = [{'arn': '', 'principle': ''}]
        session.assertion = assertion
        sts = {'Credentials':
               {'AccessKeyId':     'AKI',
                'SecretAccessKey': 'squirrel',
                'SessionToken':    'token',
                'Expiration':      'never'
                }}
        session.sts = mock.Mock()
        session.sts.assume_role_with_saml.return_value = sts

        session.assume_role(print_only=True)

        assert not mock_write.called
        assert mock_print.called

    @mock.patch('aws_okta_keyman.aws.Session._write')
    def test_assume_role_duration_rejected(self, mock_write):
        mock_write.return_value = None
        assertion = mock.Mock()
        assertion.roles.return_value = [{'arn': '', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.duration = 1000000
        session.roles = [{'arn': '', 'principle': ''}]
        session.assertion = assertion
        sts = {'Credentials':
               {'AccessKeyId':     'AKI',
                'SecretAccessKey': 'squirrel',
                'SessionToken':    'token',
                'Expiration':      'never'
                }}
        session.sts = mock.Mock()
        err_mock = mock.MagicMock()
        err = botocore.exceptions.ClientError(err_mock, err_mock)
        session.sts.assume_role_with_saml.side_effect = [err, sts]

        session.assume_role()

        self.assertEqual('AKI', session.creds['AccessKeyId'])
        self.assertEqual('squirrel', session.creds['SecretAccessKey'])
        self.assertEqual('token', session.creds['SessionToken'])
        self.assertEqual('never', session.creds['Expiration'])
        session.sts.assert_has_calls([
            mock.call.assume_role_with_saml(
                RoleArn='',
                PrincipalArn='',
                SAMLAssertion=mock.ANY,
                DurationSeconds=1000000),
            mock.call.assume_role_with_saml(
                RoleArn='',
                PrincipalArn='',
                SAMLAssertion=mock.ANY,
                DurationSeconds=3600),
        ])

    @mock.patch('aws_okta_keyman.aws.LOG')
    def test_print_creds(self, log_mock):
        session = aws.Session('BogusAssertion')
        expected = (
            'AWS Credentials: \n\n\n'
            'AWS_ACCESS_KEY_ID = None\n'
            'AWS_SECRET_ACCESS_KEY = None\n'
            'AWS_SESSION_TOKEN = None\n\n'
        )

        session._print_creds()

        log_mock.assert_has_calls([
            mock.call.info(expected)
        ])

    @mock.patch('aws_okta_keyman.aws.requests')
    def test_generate_aws_console_url(self, requests_mock):
        session = aws.Session('BogusAssertion')
        session.duration = 3600
        session.creds = {'AccessKeyId':     'AKI',
                         'SecretAccessKey': 'squirrel',
                         'SessionToken':    'token',
                         'Expiration':      'never'
                         }
        resp_mock = mock.MagicMock()
        resp_mock.json.return_value = {'SigninToken': 'baz'}
        requests_mock.get.return_value = resp_mock

        issuer = 'https://ex.okta.com/foo/bar'
        ret = session.generate_aws_console_url(issuer)

        expected = (
            "https://signin.aws.amazon.com/federation?Action=login&Issuer="
            "https://ex.okta.com/foo/bar&Destination="
            "https%3A//console.aws.amazon.com/&SigninToken=baz")
        self.assertEqual(ret, expected)
        # mock.ANY required for the session due to Python 3.5 behavior
        requests_mock.assert_has_calls([
            mock.call.get(
                'https://signin.aws.amazon.com/federation',
                params={
                    'Action': 'getSigninToken',
                    'SessionDuration': 3600,
                    'Session': mock.ANY}),
            mock.call.get().json()
        ])

    def test_export_creds_to_var_string(self):
        session = aws.Session('BogusAssertion')
        expected = (
            'export AWS_ACCESS_KEY_ID=None; '
            'export AWS_SECRET_ACCESS_KEY=None; '
            'export AWS_SESSION_TOKEN=None;'
        )

        ret = session.export_creds_to_var_string()

        self.assertEqual(ret, expected)

    def test_available_roles(self):
        roles = [{'role': '::::1:role/role1', 'principle': ''},
                 {'role': '::::1:role/role3', 'principle': ''},
                 {'role': '::::1:role/role2', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.assertion = mock.MagicMock()
        session.assertion.roles.return_value = roles

        result = session.available_roles()

        print(result)

        expected = [
            {'account': '1', 'role_name': 'role1',
             'principle': '', 'arn': '::::1:role/role1',
             'roleIdx': 0},
            {'account': '1', 'role_name': 'role2',
             'principle': '', 'arn': '::::1:role/role2',
             'roleIdx': 1},
            {'account': '1', 'role_name': 'role3',
             'principle': '', 'arn': '::::1:role/role3',
             'roleIdx': 2}
            ]

        self.assertEqual(expected, result)

    def test_available_roles_multiple_accounts(self):
        roles = [{'role': '::::1:role/role', 'principle': ''},
                 {'role': '::::2:role/role', 'principle': ''}]
        roles_full = [{'account': '1', 'role_name': 'role',
                       'arn': '::::1:role/role', 'principle': ''},
                      {'account': '2', 'role_name': 'role',
                       'arn': '::::2:role/role', 'principle': ''}]
        session = aws.Session('BogusAssertion')
        session.assertion = mock.MagicMock()
        session.assertion.roles.return_value = roles
        session.account_ids_to_names = mock.MagicMock()
        session.account_ids_to_names.return_value = roles_full
        expected = [
            {'account': '1', 'role_name': 'role',
             'principle': '', 'arn': '::::1:role/role', 'roleIdx': 0},
            {'account': '2', 'role_name': 'role',
             'principle': '', 'arn': '::::2:role/role', 'roleIdx': 1}
            ]

        result = session.available_roles()

        print(result)
        self.assertEqual(expected, result)

    def test_account_ids_to_names_map(self):
        session = aws.Session('BogusAssertion')
        session.get_account_name_map = mock.MagicMock()
        account_map = {'1': 'One', '2': 'Two'}
        session.get_account_name_map.return_value = account_map
        roles = [{'role': 'role', 'account': '1'},
                 {'role': 'role', 'account': '2'}]
        expected = [{'account': 'One', 'role': 'role'},
                    {'account': 'Two', 'role': 'role'}]

        ret = session.account_ids_to_names(roles)

        self.assertEqual(ret, expected)

    def test_account_ids_to_names_call_failed(self):
        session = aws.Session('BogusAssertion')
        session.get_account_name_map = mock.MagicMock()
        session.get_account_name_map.side_effect = Exception()
        roles = [{'role': '::::1:role'},
                 {'role': '::::2:role'}]
        ret = session.account_ids_to_names(roles)

        self.assertEqual(ret, [{'role': '::::1:role'}, {'role': '::::2:role'}])

    def test_get_account_name_map(self):
        def post(*args, **kwargs):
            return MockResponse('html')

        session = aws.Session('BogusAssertion')
        session.assertion = mock.MagicMock()
        session.assertion.encode.response_value = ''
        session.account_names_from_html = mock.MagicMock()
        session.account_names_from_html.return_value = {}

        with mock.patch('aws_okta_keyman.aws.requests.post', side_effect=post):
            ret = session.get_account_name_map()

        self.assertEqual(ret, {})
        session.account_names_from_html.assert_has_calls([mock.call('html')])

    def test_get_account_name_map_error(self):
        def post(*args, **kwargs):
            return MockResponse('text', True)

        session = aws.Session('BogusAssertion')
        session.assertion = mock.MagicMock()
        session.assertion.encode.response_value = ''

        with mock.patch('aws_okta_keyman.aws.requests.post', side_effect=post):
            with self.assertRaises(Exception):
                session.get_account_name_map()

    def test_account_names_from_html(self):
        session = aws.Session('BogusAssertion')
        ret = session.account_names_from_html(AWS_HTML_MULTIACCOUNT_LOGIN)
        self.assertEqual(ret, {'123456': 'my-dev', '123457': 'my-prod'})
