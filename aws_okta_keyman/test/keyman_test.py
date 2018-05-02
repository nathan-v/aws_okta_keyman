from __future__ import unicode_literals

import logging
import sys
import unittest

from aws_okta_keyman import aws, okta
from aws_okta_keyman.keyman import Keyman

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class KeymanTest(unittest.TestCase):

    def test_setup_logging(self):
        # Simple execution test - make sure that the logger code executes and
        # returns a root logger. No mocks used here, want to ensure that the
        # options passed to the logger are valid.
        ret = Keyman.setup_logging()
        self.assertEquals(type(ret), type(logging.getLogger()))

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_init_blank_args(self, _config_mock):
        keyman = Keyman([''])
        assert isinstance(keyman, Keyman)

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_init_use_debug(self, config_mock):
        config_mock().debug = True
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz', '-D'])
        log_level = logging.getLevelName(keyman.log.getEffectiveLevel())
        self.assertEqual('DEBUG', log_level)

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_init_bad_config(self, config_mock):
        config_mock().get_config.side_effect = ValueError
        with self.assertRaises(SystemExit):
            Keyman([])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.return_value = 'foo'
        keyman.init_okta = mock.MagicMock()
        keyman.auth_okta = mock.MagicMock()
        keyman.aws_auth_loop = mock.MagicMock()

        keyman.main()

        assert keyman.handle_appid_selection.called
        assert keyman.user_password.called
        keyman.init_okta.assert_called_with('foo')
        assert keyman.auth_okta.called
        assert keyman.aws_auth_loop.called

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_keyboard_interrupt(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.side_effect = KeyboardInterrupt

        with self.assertRaises(SystemExit):
            keyman.main()

    @mock.patch('aws_okta_keyman.keyman.input')
    def test_user_input(self, input_mock):
        input_mock.return_value = 'test'
        self.assertEqual('test', Keyman.user_input('input test'))

    @mock.patch('aws_okta_keyman.keyman.getpass')
    def test_user_password(self, pass_mock):
        pass_mock.getpass.return_value = 'test'
        self.assertEqual('test', Keyman.user_password())

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_selector_menu(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        stdout_mock = mock.Mock()
        sys.stdout = stdout_mock
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = 0
        stuff = [{'artist': 'Metallica'},
                 {'artist': 'Soundgarden'}]
        ret = keyman.selector_menu(stuff, 'artist', 'Artist')
        self.assertEqual(ret, 0)
        stdout_mock.assert_has_calls([
            mock.call.write('[0] Artist: Metallica'),
            mock.call.write('\n'),
            mock.call.write('[1] Artist: Soundgarden'),
            mock.call.write('\n')
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_selector_menu_keep_asking_if_out_of_range(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        stdout_mock = mock.Mock()
        sys.stdout = stdout_mock
        keyman.user_input = mock.MagicMock()
        keyman.user_input.side_effect = [99, 98, 0]
        stuff = [{'artist': 'Metallica'},
                 {'artist': 'Soundgarden'}]
        ret = keyman.selector_menu(stuff, 'artist', 'Artist')
        self.assertEqual(ret, 0)
        keyman.user_input.assert_has_calls([
            mock.call('Artist selection: '),
            mock.call('Artist selection: '),
            mock.call('Artist selection: ')
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = [{'name': 'myAccount', 'appid': 'myID'}]
        keyman.config.appid = None
        keyman.selector_menu = mock.MagicMock(name='selector_menu')
        keyman.selector_menu.return_value = 0
        keyman.config.set_appid_from_account_id = mock.MagicMock()

        keyman.handle_appid_selection()

        keyman.selector_menu.assert_has_calls([
            mock.call(
                [{'name': 'myAccount', 'appid': 'myID'}],
                'name', 'Account')
        ])
        keyman.config.set_appid_from_account_id.assert_has_calls([
            mock.call(0)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection_when_appid_provided(self, config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        config_mock().appid = 'someid'
        self.assertEqual(keyman.handle_appid_selection(), None)

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.okta_saml')
    def test_init_okta(self, okta_mock, _config_mock):
        okta_mock.OktaSaml = mock.MagicMock()
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.init_okta('troz')

        okta_mock.OktaSaml.assert_has_calls([
            mock.call(mock.ANY, mock.ANY, 'troz')
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.okta_saml')
    def test_init_okta_with_oktapreview(self, okta_mock, _config_mock):
        okta_mock.OktaSaml = mock.MagicMock()
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.config.oktapreview = True
        keyman.init_okta('troz')

        okta_mock.OktaSaml.assert_has_calls([
            mock.call(mock.ANY, mock.ANY, 'troz', oktapreview=True)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.okta_saml')
    def test_init_okta_with_empty_input(self, okta_mock, _config_mock):
        okta_mock.EmptyInput = BaseException
        okta_mock.OktaSaml = mock.MagicMock()
        okta_mock.OktaSaml.side_effect = okta.EmptyInput
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        with self.assertRaises(SystemExit):
            keyman.init_okta('troz')

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.return_value = None

        ret = keyman.auth_okta()
        self.assertEqual(ret, None)

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_bad_password(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.side_effect = okta.InvalidPassword

        with self.assertRaises(SystemExit):
            keyman.auth_okta()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_mfa(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.side_effect = okta.PasscodeRequired('a', 'b',
                                                                    'c')
        keyman.okta_client.validate_mfa.return_value = True
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = '000000'

        keyman.auth_okta()

        keyman.okta_client.validate_mfa.assert_has_calls([
            mock.call('a', 'b', '000000'),
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_mfa_retry(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.side_effect = okta.PasscodeRequired('a', 'b',
                                                                    'c')
        keyman.okta_client.validate_mfa.side_effect = [False, True]
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = '000000'

        keyman.auth_okta()

        keyman.okta_client.validate_mfa.assert_has_calls([
            mock.call('a', 'b', '000000'),
            mock.call('a', 'b', '000000'),
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_answer(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        factor = {'id': 'foo', 'profile': {'questionText': 'a'}}
        keyman.okta_client.auth.side_effect = okta.AnswerRequired(factor, 'b')
        keyman.okta_client.validate_answer.return_value = True
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = 'Someanswer'

        keyman.auth_okta()

        keyman.okta_client.validate_answer.assert_has_calls([
            mock.call('foo', 'b', 'Someanswer'),
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_answer_retry(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        factor = {'id': 'foo', 'profile': {'questionText': 'a'}}
        keyman.okta_client.auth.side_effect = okta.AnswerRequired(factor, 'b')
        keyman.okta_client.validate_answer.side_effect = [False, True]
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = 'Someanswer'

        keyman.auth_okta()

        keyman.okta_client.validate_answer.assert_has_calls([
            mock.call('foo', 'b', 'Someanswer'),
            mock.call('foo', 'b', 'Someanswer'),
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_unknown_error(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.side_effect = okta.UnknownError

        with self.assertRaises(SystemExit):
            keyman.auth_okta()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_multiple_roles(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.selector_menu = mock.MagicMock()
        keyman.selector_menu.return_value = 0
        roles = [{}, {}]
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        ret = keyman.handle_multiple_roles(mock_session)

        self.assertEqual(ret, 0)

        keyman.selector_menu.assert_has_calls([
            mock.call([{}, {}], 'role', 'Role')
        ])
        mock_session.assert_has_calls([
            mock.call.available_roles(),
            mock.call.set_role(mock.ANY),
            mock.call.assume_role()
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.aws')
    def test_start_session(self, aws_mock, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.get_assertion.return_value = 'assertion'
        aws_mock.Session = mock.MagicMock()

        keyman.start_session()

        keyman.okta_client.assert_has_calls([
            mock.call.get_assertion(appid=mock.ANY, apptype='amazon_aws')
        ])
        aws_mock.assert_has_calls([
            mock.call.Session('assertion', profile=mock.ANY)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_start_session_failure(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.get_assertion.side_effect = okta.UnknownError

        with self.assertRaises(SystemExit):
            keyman.start_session()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop(self, config_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()

        keyman.aws_auth_loop()

        keyman.start_session.assert_has_calls([
            mock.call(),
            mock.call().assume_role()
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_multirole(self, config_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()
        keyman.start_session().assume_role.side_effect = aws.MultipleRoles
        keyman.handle_multiple_roles = mock.MagicMock()

        keyman.aws_auth_loop()

        keyman.handle_multiple_roles.assert_has_calls([
            mock.call(mock.ANY)
        ])
