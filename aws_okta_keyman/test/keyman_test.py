# -*- coding: UTF-8 -*-
from __future__ import unicode_literals

import logging
import sys
import unittest
import xml

from aws_okta_keyman import aws, okta, duo
from aws_okta_keyman.keyman import Keyman, NoAWSAccounts
from aws_okta_keyman.metadata import __version__

import botocore
import keyring
import requests

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class KeymanTest(unittest.TestCase):

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
        keyman.aws_auth_loop.return_value = None

        keyman.main()

        assert keyman.handle_appid_selection.called
        assert keyman.user_password.called
        keyman.init_okta.assert_called_with('foo')
        assert keyman.auth_okta.called
        assert keyman.aws_auth_loop.called

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_post_okta_appid_selection(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.config.appid = None
        keyman.user_password = mock.MagicMock()
        keyman.user_password.return_value = 'foo'
        keyman.init_okta = mock.MagicMock()
        keyman.auth_okta = mock.MagicMock()
        keyman.aws_auth_loop = mock.MagicMock()
        keyman.aws_auth_loop.return_value = None
        keyman.handle_appid_selection = mock.MagicMock()

        keyman.main()

        keyman.handle_appid_selection.assert_has_calls([
            mock.call(),
            mock.call(okta_ready=True)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_keyboard_interrupt(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.side_effect = KeyboardInterrupt

        with self.assertRaises(SystemExit):
            keyman.main()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_unhandled_exception(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.side_effect = Exception()

        with self.assertRaises(SystemExit):
            keyman.main()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_aws_auth_error(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.handle_appid_selection.side_effect = NoAWSAccounts()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.return_value = 'foo'
        keyman.init_okta = mock.MagicMock()
        keyman.auth_okta = mock.MagicMock()
        keyman.aws_auth_loop = mock.MagicMock()

        with self.assertRaises(SystemExit):
            keyman.main()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_no_aws_accounts(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.return_value = 'foo'
        keyman.init_okta = mock.MagicMock()
        keyman.auth_okta = mock.MagicMock()
        keyman.aws_auth_loop = mock.MagicMock()
        keyman.aws_auth_loop.return_value = 1

        with self.assertRaises(SystemExit):
            keyman.main()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_main_update(self, config_mock):
        config_mock().update = True
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.update = mock.MagicMock()
        keyman.handle_appid_selection = mock.MagicMock()
        keyman.user_password = mock.MagicMock()
        keyman.user_password.return_value = 'foo'
        keyman.init_okta = mock.MagicMock()
        keyman.auth_okta = mock.MagicMock()
        keyman.aws_auth_loop = mock.MagicMock()

        with self.assertRaises(SystemExit):
            keyman.main()

        keyman.update.assert_has_calls([mock.call(__version__)])

    @mock.patch('aws_okta_keyman.keyman.input')
    def test_user_input(self, input_mock):
        input_mock.return_value = ' test '

        self.assertEqual('test', Keyman.user_input('input test'))

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.getpass')
    def test_user_password_no_cache(self, pass_mock, _config_mock):
        keyman = Keyman('')
        keyman.config.password_cache = False
        pass_mock.getpass.return_value = 'test'

        self.assertEqual('test', keyman.user_password())

    @mock.patch('aws_okta_keyman.keyman.keyring.get_password')
    @mock.patch('aws_okta_keyman.keyman.keyring.get_keyring')
    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.getpass')
    def test_user_password_cache_unavailable(self, pass_mock, _config_mock,
                                             keyring_kr_mock, keyring_pw_mock):
        keyman = Keyman('')
        keyman.config.password_cache = True
        keyman.config.password_reset = False
        keyring_kr_mock.side_effect = keyring.errors.InitError
        pass_mock.getpass.return_value = 'test'

        self.assertEqual('test', keyman.user_password())
        assert not keyring_pw_mock.called

    @mock.patch('aws_okta_keyman.keyman.keyring.get_password')
    @mock.patch('aws_okta_keyman.keyman.keyring.get_keyring')
    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.getpass')
    def test_user_password_cache_get_success(self, pass_mock, _config_mock,
                                             keyring_kr_mock, keyring_pw_mock):
        keyman = Keyman('')
        keyman.config.password_cache = True
        keyman.config.password_reset = False
        keyring_pw_mock.return_value = 'test'

        self.assertEqual('test', keyman.user_password())
        assert not pass_mock.called

    @mock.patch('aws_okta_keyman.keyman.keyring.set_password')
    @mock.patch('aws_okta_keyman.keyman.keyring.get_password')
    @mock.patch('aws_okta_keyman.keyman.keyring.get_keyring')
    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.getpass')
    def test_user_password_cache_get_empty(self, pass_mock, _config_mock,
                                           keyring_kr_mock, keyring_pw_mock,
                                           keyring_setpw_mock):
        keyman = Keyman('')
        keyman.config.password_cache = True
        keyman.config.password_reset = False
        keyring_pw_mock.return_value = None
        pass_mock.getpass.return_value = 'test'

        self.assertEqual('test', keyman.user_password())
        keyring_setpw_mock.assert_has_calls([
            mock.call('aws_okta_keyman', mock.ANY, 'test')
        ])

    def test_generate_template_long_data(self):
        header = [{'artist': 'Artist'}, {'album': 'Album'}]
        data = [
            {'artist': 'Metallica', 'album': 'Metallica'},
            {'artist': 'Soundgarden', 'album': 'Superunknown'}
        ]
        ret = Keyman.generate_template(data, header)

        self.assertEqual(ret, '{artist:13}{album:14}')

    def test_generate_template_long_header(self):
        header = [{'artist': 'Full Artist Name'}, {'album': 'Full Album Name'}]
        data = [
            {'artist': 'Lite', 'album': 'Cubic'},
            {'artist': 'toe', 'album': 'Hear You'}
        ]
        ret = Keyman.generate_template(data, header)

        self.assertEqual(ret, '{artist:18}{album:17}')

    def test_generate_header(self):
        source = [{'artist': 'Artist'}, {'album': 'Album'}]
        output = {'artist': 'Artist', 'album': 'Album'}

        self.assertEqual(Keyman.generate_header(source), output)

    @mock.patch('sys.stdout')
    def test_print_selector_table(self, stdout_mock):
        keyman = Keyman
        Keyman.generate_header = mock.MagicMock()
        formatted_header = {'artist': 'Artist', 'album': 'Album'}
        Keyman.generate_header.return_value = formatted_header
        data = [
            {'artist': 'Metallica', 'album': 'Metallica'},
            {'artist': 'Soundgarden', 'album': 'Superunknown'}
        ]
        header = [{'artist': 'Artist'}]
        template = '{artist:13}{album:14}'

        keyman.print_selector_table(template, header, data)

        stdout_mock.assert_has_calls([
            mock.call.write('\n    Artist       Album         '),
            mock.call.write('\n'),
            mock.call.write('[0] Metallica    Metallica     '),
            mock.call.write('\n'),
            mock.call.write('[1] Soundgarden  Superunknown  '),
            mock.call.write('\n')
        ])

    def test_update_current(self):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.get_pip_version = mock.MagicMock()
        keyman.get_pip_version.return_value = __version__
        keyman.log = mock.MagicMock()

        keyman.update(__version__)

        keyman.log.info.assert_has_calls([
            mock.call('Keyman is up to date')
        ])

    @mock.patch('aws_okta_keyman.keyman.platform')
    @mock.patch('aws_okta_keyman.keyman.subprocess')
    def test_update_old_pip(self, subp_mock, plat_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.get_pip_version = mock.MagicMock()
        keyman.get_pip_version.return_value = '100000'
        keyman.log = mock.MagicMock()
        plat_mock.system.return_value = "Linux"
        subp_mock.check_call.return_value = 0

        keyman.update(__version__)

        keyman.log.info.assert_has_calls([
            mock.call('New version 100000. Updaing..')
        ])
        subp_mock.assert_has_calls([
            mock.call.check_call([
                mock.ANY, '-m', 'pip', 'install',
                '--upgrade', 'aws-okta-keyman'
            ])
        ])

    @mock.patch('aws_okta_keyman.keyman.platform')
    @mock.patch('aws_okta_keyman.keyman.subprocess')
    def test_update_old_brew(self, subp_mock, plat_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.get_pip_version = mock.MagicMock()
        keyman.get_pip_version.return_value = '100000'
        keyman.log = mock.MagicMock()
        plat_mock.system.return_value = "Darwin"
        subp_mock.check_call.return_value = 0

        keyman.update(__version__)

        keyman.log.info.assert_has_calls([
            mock.call('New version 100000. Updaing..')
        ])
        subp_mock.assert_has_calls([
            mock.call.check_call([u'brew', u'upgrade', u'aws_okta_keyman'])
        ])

    @mock.patch('aws_okta_keyman.keyman.subprocess')
    def test_update_old_failed(self, subp_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.get_pip_version = mock.MagicMock()
        keyman.get_pip_version.return_value = '100000'
        keyman.log = mock.MagicMock()
        subp_mock.check_call.return_value = 1

        keyman.update(__version__)

        keyman.log.warning.assert_has_calls([
            mock.call('Error updating Keyman. Please try updating manually.')
        ])

    @mock.patch('aws_okta_keyman.keyman.requests')
    def test_get_pip_version(self, requests_mock):
        resp = {'info': {'version': '1.0'}}
        resp_mock = mock.MagicMock()
        resp_mock.json.return_value = resp
        requests_mock.get.return_value = resp_mock

        ret = Keyman.get_pip_version()

        self.assertEqual(ret, '1.0')
        requests_mock.assert_has_calls([
            mock.call.get(u'https://pypi.org/pypi/aws-okta-keyman/json')
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_selector_menu(self, _config_mock):
        keyman = Keyman(['foo'])
        Keyman.generate_template = mock.MagicMock()
        Keyman.print_selector_table = mock.MagicMock()
        keyman.user_input = mock.MagicMock()
        keyman.user_input.side_effect = ['invalid', '', 0]
        stuff = [{'artist': 'Metallica'},
                 {'artist': 'Soundgarden'}]
        header = [{'artist': 'Artist'}]

        ret = keyman.selector_menu(stuff, header)

        self.assertEqual(ret, 0)
        keyman.user_input.assert_has_calls([
            mock.call('Selection: '),
            mock.call('Selection: '),
            mock.call('Selection: ')
        ])
        Keyman.generate_template.assert_has_calls([
            mock.call(
                [{'artist': 'Metallica'}, {'artist': 'Soundgarden'}],
                [{'artist': 'Artist'}]),
        ])
        Keyman.print_selector_table.assert_has_calls([
            mock.call(
                mock.ANY,
                [{'artist': 'Artist'}],
                [{'artist': 'Metallica'}, {'artist': 'Soundgarden'}]),
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_selector_menu_keep_asking_if_invalid(self, _config_mock):
        keyman = Keyman(['foo'])
        Keyman.generate_template = mock.MagicMock()
        Keyman.print_selector_table = mock.MagicMock()
        keyman.user_input = mock.MagicMock()
        keyman.user_input.side_effect = ['invalid', '', 0]
        stuff = [{'artist': 'Metallica'},
                 {'artist': 'Soundgarden'}]
        header = [{'artist': 'Artist'}]

        ret = keyman.selector_menu(stuff, header)

        self.assertEqual(ret, 0)
        keyman.user_input.assert_has_calls([
            mock.call('Selection: '),
            mock.call('Selection: '),
            mock.call('Selection: ')
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = [
            {'name': 'myAccount', 'appid': 'myID'},
            {'name': 'myAccount', 'appid': 'myID'}
        ]
        keyman.config.appid = None
        keyman.selector_menu = mock.MagicMock(name='selector_menu')
        keyman.selector_menu.return_value = 0
        keyman.config.set_appid_from_account_id = mock.MagicMock()

        keyman.handle_appid_selection()

        keyman.selector_menu.assert_has_calls([
            mock.call([
                {'name': 'myAccount', 'appid': 'myID'},
                {'name': 'myAccount', 'appid': 'myID'}],
                [{'name': 'Account'}])
        ])
        keyman.config.set_appid_from_account_id.assert_has_calls([
            mock.call(0)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection_one_account(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = [{'name': 'myAccount', 'appid': 'myID'}]
        keyman.config.appid = None
        keyman.config.set_appid_from_account_id = mock.MagicMock()
        keyman.handle_appid_selection()

        keyman.config.set_appid_from_account_id.assert_has_calls([
            mock.call(0)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection_no_appid(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = None
        keyman.config.appid = None
        keyman.selector_menu = mock.MagicMock(name='selector_menu')
        keyman.selector_menu.return_value = 0
        keyman.config.set_appid_from_account_id = mock.MagicMock()

        ret = keyman.handle_appid_selection()

        self.assertEqual(ret, None)

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection_from_okta(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = None
        keyman.config.appid = None
        keyman.selector_menu = mock.MagicMock(name='selector_menu')
        keyman.selector_menu.return_value = 0
        keyman.config.set_appid_from_account_id = mock.MagicMock()
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.get_aws_apps.return_value = [
            {'name': 'myAccount', 'appid': 'myID'}
        ]

        keyman.handle_appid_selection(okta_ready=True)

        assert keyman.okta_client.get_aws_apps.called

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_appid_selection_from_okta_no_aws(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = None
        keyman.config.appid = None
        keyman.selector_menu = mock.MagicMock(name='selector_menu')
        keyman.selector_menu.return_value = 0
        keyman.config.set_appid_from_account_id = mock.MagicMock()
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.get_aws_apps.return_value = []

        with self.assertRaises(NoAWSAccounts):
            keyman.handle_appid_selection(okta_ready=True)

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_duo_factor_selection(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar'])
        keyman.config.accounts = [{'name': 'myAccount', 'appid': 'myID'}]
        keyman.config.appid = None
        keyman.selector_menu = mock.MagicMock(name='selector_menu')
        keyman.selector_menu.return_value = 0
        keyman.config.set_appid_from_account_id = mock.MagicMock()

        ret = keyman.handle_duo_factor_selection()

        keyman.selector_menu.assert_has_calls([
            mock.call([
                {'name': '📲 Duo Push', 'factor': 'push'},
                {'name': '📟 OTP Passcode', 'factor': 'passcode'},
                {'name': '📞 Phone call', 'factor': 'call'}],
                [{'name': 'Duo Factor'}])
        ])
        self.assertEqual(ret, 'push')

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
            mock.call(mock.ANY, mock.ANY, 'troz', duo_factor=mock.ANY)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.okta_saml')
    def test_init_okta_with_oktapreview(self, okta_mock, _config_mock):
        okta_mock.OktaSaml = mock.MagicMock()
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.config.oktapreview = True

        keyman.init_okta('troz')

        okta_mock.OktaSaml.assert_has_calls([
            mock.call(mock.ANY, mock.ANY, 'troz', mock.ANY, oktapreview=True)
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
    @mock.patch('aws_okta_keyman.keyman.okta_saml')
    def test_init_okta_with_duo_factor(self, okta_mock, _config_mock):
        okta_mock.OktaSaml = mock.MagicMock()
        keyman = Keyman(
            ['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz', '-d', 'push'])

        keyman.init_okta('troz')

        okta_mock.OktaSaml.assert_has_calls([
            mock.call(mock.ANY, mock.ANY, 'troz', duo_factor=mock.ANY)
        ])

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
    def test_auth_okta_duo_mfa_no_factor(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.handle_duo_factor_selection = mock.MagicMock()
        keyman.okta_client.auth.side_effect = [duo.FactorRequired('a', 'b'),
                                               True]
        keyman.okta_client.duo_auth.side_effect = [False, True]
        keyman.user_input = mock.MagicMock()

        keyman.auth_okta()

        keyman.handle_duo_factor_selection.assert_has_calls([mock.call()])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_duo_mfa_passcode(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.side_effect = duo.PasscodeRequired('a', 'b')
        keyman.okta_client.duo_auth.return_value = True
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = '000000'

        keyman.auth_okta()

        keyman.okta_client.duo_auth.assert_has_calls([
            mock.call('a', 'b', '000000'),
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_auth_okta_duo_mfa_passcode_retry(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.auth.side_effect = duo.PasscodeRequired('a', 'b')
        keyman.okta_client.duo_auth.side_effect = [False, True]
        keyman.user_input = mock.MagicMock()
        keyman.user_input.return_value = '000000'

        keyman.auth_okta()

        keyman.okta_client.duo_auth.assert_has_calls([
            mock.call('a', 'b', '000000'),
            mock.call('a', 'b', '000000'),
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
        roles = ([
          {'account': 'acct1', 'role_name': 'role1', 'roleIdx': 0},
          {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1}
        ])
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        keyman.config.account = None
        keyman.config.role = None

        keyman.handle_multiple_roles(mock_session)

        keyman.selector_menu.assert_has_calls([
            mock.call(roles,
                      [{'account': 'Account'}, {'role_name': 'Role'}])
        ])
        mock_session.assert_has_calls([
            mock.call.available_roles()
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_multiple_roles_account_match(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.selector_menu = mock.MagicMock()
        keyman.selector_menu.return_value = 1
        roles = ([
            {'account': 'acct1', 'role_name': 'role1', 'roleIdx': 0},
            {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1},
            {'account': 'acct2', 'role_name': 'role1', 'roleIdx': 2},
            {'account': 'acct2', 'role_name': 'role2', 'roleIdx': 3}
        ])
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        keyman.config.account = 'acct2'
        keyman.config.role = None

        assert keyman.handle_multiple_roles(mock_session)
        # item 1 "selected" from menu translates to role #3
        assert keyman.role == 3

        keyman.selector_menu.assert_has_calls([
            mock.call(
                  ([
                    {'account': 'acct2', 'role_name': 'role1', 'roleIdx': 2},
                    {'account': 'acct2', 'role_name': 'role2', 'roleIdx': 3}
                  ]),
                  [{'account': 'Account'}, {'role_name': 'Role'}])
        ])

        mock_session.assert_has_calls([
            mock.call.available_roles()
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_multiple_roles_rollname_match(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.selector_menu = mock.MagicMock()
        keyman.selector_menu.return_value = 0
        roles = ([
            {'account': 'acct1', 'role_name': 'role1', 'roleIdx': 0},
            {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1},
            {'account': 'acct2', 'role_name': 'role1', 'roleIdx': 2},
            {'account': 'acct2', 'role_name': 'role2', 'roleIdx': 3}
        ])
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        keyman.config.account = None
        keyman.config.role = 'role2'

        assert keyman.handle_multiple_roles(mock_session)
        # item 0 "selected" from menu translates to role #1
        assert keyman.role == 1

        keyman.selector_menu.assert_has_calls([
            mock.call(
                  ([
                    {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1},
                    {'account': 'acct2', 'role_name': 'role2', 'roleIdx': 3}
                  ]),
                  [{'account': 'Account'}, {'role_name': 'Role'}])
        ])

        mock_session.assert_has_calls([
            mock.call.available_roles()
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_multiple_roles_single_role_match(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.selector_menu = mock.MagicMock()
        keyman.selector_menu.return_value = 0
        roles = ([
            {'account': 'acct1', 'role_name': 'role1', 'roleIdx': 0},
            {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1},
            {'account': 'acct2', 'role_name': 'role1', 'roleIdx': 2},
            {'account': 'acct2', 'role_name': 'role2', 'roleIdx': 3}
        ])
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        keyman.config.account = 'acct1'
        keyman.config.role = 'role2'

        assert keyman.handle_multiple_roles(mock_session)
        assert keyman.role == 1

        keyman.selector_menu.assert_not_called()

        mock_session.assert_has_calls([
            mock.call.available_roles()
        ])

    # multiple accounts with no matching account
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_multiple_roles_no_match_account(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.selector_menu = mock.MagicMock()
        keyman.selector_menu.return_value = 0
        roles = ([
            {'account': 'acct1', 'role_name': 'role1', 'roleIdx': 0},
            {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1},
            {'account': 'acct2', 'role_name': 'role1', 'roleIdx': 2}
        ])
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        keyman.config.account = 'acct3'
        keyman.config.role = None

        assert not keyman.handle_multiple_roles(mock_session)

        keyman.selector_menu.assert_not_called()

        mock_session.assert_has_calls([
            mock.call.available_roles()
        ])

    # multiple accounts with no matching role
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_handle_multiple_roles_no_match_role(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.selector_menu = mock.MagicMock()
        keyman.selector_menu.return_value = 0
        roles = ([
            {'account': 'acct1', 'role_name': 'role1', 'roleIdx': 0},
            {'account': 'acct1', 'role_name': 'role2', 'roleIdx': 1},
            {'account': 'acct2', 'role_name': 'role1', 'roleIdx': 2}
        ])
        mock_session = mock.MagicMock()
        mock_session.available_roles.return_value = roles

        keyman.config.account = 'role3'
        keyman.config.role = None

        assert not keyman.handle_multiple_roles(mock_session)

        keyman.selector_menu.assert_not_called()

        mock_session.assert_has_calls([
            mock.call.available_roles()
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
            mock.call.get_assertion(appid=mock.ANY)
        ])
        aws_mock.assert_has_calls([
            mock.call.Session('assertion', profile=mock.ANY, role=None,
                              region=mock.ANY, session_duration=mock.ANY)
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_start_session_okta_failure(self, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        keyman.okta_client.get_assertion.side_effect = okta.UnknownError

        with self.assertRaises(okta.UnknownError):
            keyman.start_session()

    @mock.patch('aws_okta_keyman.keyman.Config')
    @mock.patch('aws_okta_keyman.keyman.aws.Session')
    def test_start_session_xml_failure(self, session_mock, _config_mock):
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.okta_client = mock.MagicMock()
        xml_error = xml.etree.ElementTree.ParseError()
        session_mock.side_effect = xml_error

        with self.assertRaises(aws.InvalidSaml):
            keyman.start_session()

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop(self, config_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()
        keyman.wrap_up = mock.MagicMock()
        keyman.handle_multiple_roles = mock.MagicMock()
        keyman.handle_multiple_roles.return_value = True

        keyman.aws_auth_loop()

        keyman.start_session.assert_has_calls([
            mock.call(),
            mock.call().assume_role(mock.ANY)
        ])
        assert keyman.wrap_up.called
        assert keyman.handle_multiple_roles.called

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_connectionerror(self, config_mock, _sleep_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()
        err = requests.exceptions.ConnectionError()
        keyman.start_session.side_effect = err

        ret = keyman.aws_auth_loop()

        assert keyman.start_session.called
        self.assertEqual(ret, 3)

    @mock.patch('time.sleep', side_effect=[None, Exception])
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_continue(self, config_mock, sleep_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.config.reup = True
        session_instance = mock.MagicMock()
        session_instance.is_valid = True
        keyman.start_session = mock.MagicMock()
        keyman.start_session.return_value = session_instance
        keyman.handle_multiple_roles = mock.MagicMock()
        keyman.handle_multiple_roles.return_value = True

        with self.assertRaises(Exception):
            keyman.aws_auth_loop()

        sleep_mock.assert_has_calls([
            mock.call(60)
        ])

        assert keyman.handle_multiple_roles.called

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_multirole_no_match(self, config_mock):
        config_mock().reup = False
        config_mock().screen = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        session_instance = mock.MagicMock()
        session_instance.assume_role.side_effect = aws.MultipleRoles
        keyman.start_session = mock.MagicMock()
        keyman.start_session.return_value = session_instance
        keyman.handle_multiple_roles = mock.MagicMock()
        keyman.handle_multiple_roles.return_value = False

        ret = keyman.aws_auth_loop()

        keyman.handle_multiple_roles.assert_has_calls([
            mock.call(mock.ANY)
        ])

        self.assertEqual(ret, 1)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_reauth(self, config_mock, _sleep_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        session_instance = mock.MagicMock()
        session_instance.assume_role.side_effect = okta.ReauthNeeded
        session_instance.is_valid = False
        keyman.start_session = mock.MagicMock()
        keyman.start_session.side_effect = session_instance, Exception()
        keyman.handle_multiple_roles = mock.MagicMock()
        keyman.auth_okta = mock.MagicMock()

        with self.assertRaises(Exception):
            keyman.aws_auth_loop()

        keyman.auth_okta.assert_has_calls([
            mock.call(state_token=None)
        ])

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_invalidsaml(self, config_mock, _sleep_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()
        keyman.start_session.side_effect = aws.InvalidSaml()
        keyman.okta_client = mock.MagicMock()

        ret = keyman.aws_auth_loop()

        assert keyman.start_session.called
        self.assertEqual(ret, 1)

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_profile_error(self, config_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()
        profile_exc = botocore.exceptions.ProfileNotFound(profile='')
        keyman.start_session.side_effect = profile_exc
        keyman.okta_client = mock.MagicMock()

        ret = keyman.aws_auth_loop()

        assert keyman.start_session.called
        self.assertEqual(ret, 4)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_aws_auth_loop_exception(self, config_mock, _sleep_mock):
        config_mock().reup = False
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.start_session = mock.MagicMock()
        keyman.start_session.side_effect = Exception()

        with self.assertRaises(Exception):
            keyman.aws_auth_loop()

        assert keyman.start_session.called

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_wrap_up_noop(self, config_mock):
        config_mock().command = None
        config_mock().console = None
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        keyman.log = mock.MagicMock()

        keyman.wrap_up(None)

        keyman.log.assert_has_calls([
            mock.call.info('All done! 👍')
        ])

    @mock.patch('aws_okta_keyman.keyman.os')
    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_wrap_up_with_command(self, config_mock, os_mock):
        config_mock().command = 'echo w00t'
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        fake_session = mock.MagicMock()
        fake_session.export_creds_to_var_string.return_value = 'foo'

        keyman.wrap_up(fake_session)

        fake_session.assert_has_calls([
            mock.call.export_creds_to_var_string()
        ])
        os_mock.assert_has_calls([
            mock.call.system('foo echo w00t')
        ])

    @mock.patch('aws_okta_keyman.keyman.Config')
    def test_wrap_up_with_console(self, config_mock):
        config_mock().command = None
        config_mock().console = True
        config_mock().full_app_url.return_value = 'url'
        keyman = Keyman(['foo', '-o', 'foo', '-u', 'bar', '-a', 'baz'])
        session = mock.MagicMock()

        keyman.wrap_up(session)

        session.assert_has_calls([
            mock.call.generate_aws_console_url('url')
        ])
        config_mock.assert_has_calls([
            mock.call().full_app_url()
        ])
