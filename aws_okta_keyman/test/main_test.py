from __future__ import unicode_literals
import unittest
import logging
import sys
from aws_okta_keyman import main
from aws_okta_keyman import aws
from aws_okta_keyman import okta
if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class MainTest(unittest.TestCase):

    def test_setup_logger(self):
        # Simple execution test - make sure that the logger code executes and
        # returns a root logger. No mocks used here, want to ensure that the
        # options passed to the logger are valid.
        ret = main.setup_logging()
        self.assertEquals(type(ret), type(logging.getLogger()))

    @mock.patch('aws_okta_keyman.aws.Session')
    @mock.patch('aws_okta_keyman.okta.OktaSaml')
    @mock.patch('aws_okta_keyman.main.Config')
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
        fake_parser.debug = True
        fake_parser.reup = 0
        config_mock.return_value = fake_parser

        main.main('test')

        okta_mock.assert_called_with('server', 'username', 'test_password')

    @mock.patch('aws_okta_keyman.main.user_input')
    @mock.patch('aws_okta_keyman.aws.Session')
    @mock.patch('aws_okta_keyman.okta.OktaSaml')
    @mock.patch('aws_okta_keyman.config.Config.get_config')
    @mock.patch('getpass.getpass')
    def test_entry_point_mfa(self, pass_mock, config_mock,
                             okta_mock, aws_mock, input_mock):
        # First call to this is the password. Second call is the mis-typed
        # passcode. Third call is a valid passcode.
        pass_mock.side_effect = ['test_password']
        input_mock.side_effect = ['123', '123456']

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

        # Ensure that getpass was called once for the password
        pass_mock.assert_has_calls([
            mock.call(),
        ])

        # Ensure that we called auth, then called validate_mfa() twice - each
        # with different passcodes. Validating that the user was indeed asked
        # for a passcode on each iteration.
        fake_okta.assert_has_calls([
            mock.call.auth(),
            mock.call.validate_mfa('test_factor_id', 'test_token', '123'),
            mock.call.validate_mfa('test_factor_id', 'test_token', '123456'),
        ])

        # Ensure that user_input was called twice; once for the bad input and
        # once for the retry
        input_mock.assert_has_calls([
            mock.call('MFA Passcode: '),
            mock.call('MFA Passcode: '),
        ])

    @mock.patch('aws_okta_keyman.main.user_input')
    @mock.patch('aws_okta_keyman.main.aws.Session')
    @mock.patch('aws_okta_keyman.okta.OktaSaml')
    @mock.patch('aws_okta_keyman.config.Config.get_config')
    @mock.patch('getpass.getpass')
    def test_entry_point_multirole(self, pass_mock, config_mock,
                                   okta_mock, aws_mock, input_mock):
        # First call to this is the password. Second call is the mis-typed
        # passcode. Third call is a valid passcode.
        pass_mock.side_effect = ['test_password']
        input_mock.side_effect = '0'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='OktaSaml')
        okta_mock.return_value = fake_okta
        aws_mock.return_value = mock.MagicMock(name='aws_mock')

        # Throw MultipleRoles to validate actions when there are multiple roles
        mocked_session = aws_mock.return_value
        mocked_session.assume_role.side_effect = [aws.MultipleRoles(), None]

        # Return multiple roles
        mocked_session.available_roles = mock.Mock()
        roles = [{'role': '1', 'principle': ''},
                 {'role': '2', 'principle': ''}]
        mocked_session.available_roles.return_value = roles

        # Make sure we don't get stuck in a loop, always have to mock out the
        # reup option.
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.reup = 0
        config_mock.return_value = fake_parser

        main.main('test')

        # Ensure that getpass was called once for the password
        pass_mock.assert_has_calls([
            mock.call(),
        ])

        # Ensure that user_input was called for the role selection
        input_mock.assert_has_calls([
            mock.call('Select a role from above: '),
        ])

    @mock.patch('aws_okta_keyman.okta.OktaSaml')
    @mock.patch('aws_okta_keyman.config.Config.get_config')
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

    @mock.patch('aws_okta_keyman.okta.OktaSaml')
    @mock.patch('aws_okta_keyman.config.Config.get_config')
    @mock.patch('getpass.getpass')
    def test_entry_point_okta_unknown(self, pass_mock, config_mock, okta_mock):
        # Mock out the password getter and return a simple password
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        fake_okta = mock.MagicMock(name='fake_okta')
        fake_okta.auth.side_effect = okta.UnknownError
        okta_mock.return_value = fake_okta

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        config_mock.return_value = fake_parser

        with self.assertRaises(SystemExit):
            main.main('test')

    @mock.patch('aws_okta_keyman.okta.OktaSaml')
    @mock.patch('aws_okta_keyman.config.Config.get_config')
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

    @mock.patch('aws_okta_keyman.main.input')
    def test_input(self, mock_input):
        mock_input.return_value = 'test'
        self.assertEqual('test', main.user_input('input test'))

    @mock.patch('aws_okta_keyman.main.main')
    def test_entry_point_func(self, main_mock):
        with self.assertRaises(SystemExit):
            main.entry_point()
