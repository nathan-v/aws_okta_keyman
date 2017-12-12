import unittest
import mock
import logging

from nd_okta_auth import main
from nd_okta_auth import okta


class MainTest(unittest.TestCase):

    def test_setup_logger(self):
        # Simple execution test - make sure that the logger code executes and
        # returns a root logger. No mocks used here, want to ensure that the
        # options passed to the logger are valid.
        ret = main.setup_logging()
        self.assertEquals(type(ret), type(logging.getLogger()))

    def test_get_config_parser(self):
        # Simple execution test again - get the argument parser and make sure
        # it looks reasonably correct. Just validating that this function has
        # major typos.

        # Also simulates the _required_ options being passed in
        argv = [
            'nd_okta_auth.py',
            '-a', 'app/id',
            '-o', 'foobar',
            '-u', 'test'
        ]
        ret = main.get_config_parser(argv)
        self.assertEquals(ret.org, 'foobar')
        self.assertEquals(ret.appid, 'app/id')
        self.assertEquals(ret.username, 'test')

    @mock.patch('nd_okta_auth.aws.Session')
    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point(self, pass_mock, config_mock, okta_mock, aws_mock):
        # Mock out the password getter and return a simple password
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        okta_mock.return_value = mock.MagicMock()
        aws_mock.return_value = mock.MagicMock()

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.org = 'server'
        fake_parser.username = 'username'
        fake_parser.username = 'username'
        fake_parser.debug = True
        fake_parser.reup = 0
        config_mock.return_value = fake_parser

        main.main('test')

        okta_mock.assert_called_with('server', 'username', 'test_password')

    @mock.patch('nd_okta_auth.aws.Session')
    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    @mock.patch('__builtin__.raw_input')
    def test_entry_point_mfa(self, raw_input_mock, pass_mock, config_mock,
                             okta_mock, aws_mock):
        # Call to getpass is the password.
        pass_mock.return_value = 'test_password'

        # First call to raw_input is the mistyped passcode.
        # Second call is the valid passcode.
        raw_input_mock.side_effect = ['123', '123456']

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='OktaSaml')
        okta_mock.return_value = fake_okta
        aws_mock.return_value = mock.MagicMock()

        # Make sure we don't get stuck in a loop, always have to mock out the
        # reup option.
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.reup = 0
        config_mock.return_value = fake_parser

        # Now, when we auth() throw a okta.PasscodeRequired exception to
        # trigger the MFA requirement. Note, this is only the manually entered
        # in passcode MFA req. OktaSaml client automatically handles Okta
        # Verify with Push MFA reqs.
        fake_okta.auth.side_effect = okta.PasscodeRequired(
            fid='test_factor_id',
            state_token='test_token')

        # Pretend that the validate_mfa() call fails the first time, and
        # succeeds the second time. This simulates a typo on the MFA code.
        fake_okta.validate_mfa.side_effect = [False, True]

        main.main('test')

        # Ensure that getpass was called for the password.
        pass_mock.assert_called_with()

        # Ensure that raw_input was called twice for the passcode,
        # once after the okta.PasscodeRequired exception was thrown,
        # and once after the passcode was found to be invalid.
        self.assertEqual(raw_input_mock.mock_calls, [
            mock.call('MFA Passcode: '),
            mock.call('MFA Passcode: '),
        ])

        # Ensure that we called auth, then called validate_mfa() twice - each
        # with different passcodes. Validating that the user was indeed asked
        # for a passcode on each iteration.
        fake_okta.assert_has_calls([
            mock.call.auth(),
            mock.call.validate_mfa('test_factor_id', 'test_token', '123'),
            mock.call.validate_mfa('test_factor_id', 'test_token', '123456'),
        ])

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point_bad_password(self, pass_mock, config_mock, okta_mock):
        # Mock out the password getter and return a simple password
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='fake_okta')
        fake_okta.auth.side_effect = okta.InvalidPassword
        okta_mock.return_value = fake_okta

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        config_mock.return_value = fake_parser

        with self.assertRaises(SystemExit):
            main.main('test')

    @mock.patch('nd_okta_auth.okta.OktaSaml')
    @mock.patch('nd_okta_auth.main.get_config_parser')
    @mock.patch('getpass.getpass')
    def test_entry_point_bad_input(self, pass_mock, config_mock, okta_mock):
        # Pretend that we got some bad input...
        pass_mock.return_value = ''
        okta_mock.side_effect = okta.EmptyInput

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        config_mock.return_value = fake_parser

        with self.assertRaises(SystemExit):
            main.main('test')
