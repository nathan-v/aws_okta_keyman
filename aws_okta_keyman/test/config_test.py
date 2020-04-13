from __future__ import unicode_literals

import os
import sys
import unittest

import yaml

from aws_okta_keyman.config import Config

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class ConfigTest(unittest.TestCase):

    def test_full_app_url(self):
        config = Config(['aws_okta_keyman.py'])
        config.org = 'example'
        config.appid = 'some/thing'

        ret = config.full_app_url()
        self.assertEqual(ret, 'https://example.okta.com/some/thing')

    def test_full_app_url_preview(self):
        config = Config(['aws_okta_keyman.py'])
        config.org = 'example'
        config.appid = 'some/thing'
        config.oktapreview = True

        ret = config.full_app_url()
        self.assertEqual(ret, 'https://example.oktapreview.com/some/thing')

    @mock.patch('aws_okta_keyman.config.sys.exit')
    @mock.patch('aws_okta_keyman.config.Config.interactive_config')
    def test_start_interactive_config(self, int_mock, exit_mock):
        Config(['aws_okta_keyman.py', 'config'])
        assert int_mock.called
        assert exit_mock.called

    @mock.patch('aws_okta_keyman.config.Config.parse_config')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_set_appid_from_account_id(self, isfile_mock, parse_mock):
        isfile_mock.return_value = True
        parse_mock.return_value = None
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.set_appid_from_account_id(0)
        self.assertEqual(config.appid, 'A123')

    def test_validate_good_with_accounts(self):
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.org = 'example'
        config.username = 'user@example.com'
        self.assertEqual(config.validate(), None)

    def test_validate_good_with_appid(self):
        config = Config(['aws_okta_keyman.py'])
        config.appid = 'A123'
        config.org = 'example'
        config.username = 'user@example.com'
        self.assertEqual(config.validate(), None)

    def test_validate_missing_org(self):
        config = Config(['aws_okta_keyman.py'])
        config.username = 'user@example.com'
        with self.assertRaises(ValueError):
            config.validate()

    @mock.patch('aws_okta_keyman.config.getpass')
    def test_validate_automatic_username_from_none(self, getpass_mock):
        getpass_mock.getuser.return_value = 'user'
        config = Config(['aws_okta_keyman.py'])
        config.org = 'example'
        config.validate()
        self.assertEqual(config.username, 'user')

    @mock.patch('aws_okta_keyman.config.getpass')
    def test_validate_automatic_username_from_partial_config(self,
                                                             getpass_mock):
        getpass_mock.getuser.return_value = 'user'
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.org = 'example'
        config.username = 'automatic-username'
        config.validate()
        self.assertEqual(config.username, 'user')

    @mock.patch('aws_okta_keyman.config.getpass')
    def test_validate_automatic_username_from_full_config(self, getpass_mock):
        getpass_mock.getuser.return_value = 'user'
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.org = 'example'
        config.username = 'automatic-username@example.com'
        config.validate()
        self.assertEqual(config.username, 'user@example.com')

    def test_validate_short_duration(self):
        config = Config(['aws_okta_keyman.py'])
        config.org = 'example'
        config.duration = 1

        with self.assertRaises(ValueError):
            config.validate()

    def test_validate_long_duration(self):
        config = Config(['aws_okta_keyman.py'])
        config.org = 'example'
        config.duration = 100000000

        with self.assertRaises(ValueError):
            config.validate()

    @mock.patch('aws_okta_keyman.config.Config.validate')
    @mock.patch('aws_okta_keyman.config.Config.parse_args')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_get_config_args_only(self, isfile_mock, parse_mock, valid_mock):
        isfile_mock.return_value = False
        parse_mock.return_value = None
        valid_mock.return_value = None

        argv = [
            'aws_okta_keyman.py',
            '-a', 'app/id',
            '-o', 'foobar',
            '-u', 'test'
        ]
        config = Config(argv)
        config.get_config()
        parse_mock.assert_has_calls([
            mock.call(),
        ])

    @mock.patch('aws_okta_keyman.config.os.path.expanduser')
    @mock.patch('aws_okta_keyman.config.Config.parse_config')
    @mock.patch('aws_okta_keyman.config.Config.validate')
    @mock.patch('aws_okta_keyman.config.Config.parse_args')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_get_config_auto_config_only(self, isfile_mock, parse_mock,
                                         valid_mock, config_mock,
                                         expuser_mock):
        isfile_mock.return_value = True
        parse_mock.return_value = None
        valid_mock.return_value = None
        config_mock.return_value = None
        expuser_mock.return_value = ''

        config = Config(['aws_okta_keyman.py'])
        config.get_config()
        parse_mock.assert_has_calls([
            mock.call(main_required=False),
        ])
        config_mock.assert_has_calls([
            mock.call('/.config/aws_okta_keyman.yml'),
        ])

    @mock.patch('aws_okta_keyman.config.Config.parse_args')
    @mock.patch('aws_okta_keyman.config.os.path.expanduser')
    @mock.patch('aws_okta_keyman.config.Config.parse_config')
    @mock.patch('aws_okta_keyman.config.Config.validate')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_get_config_specified_config_only(self, isfile_mock, valid_mock,
                                              config_mock, expuser_mock,
                                              _parse_mock):
        isfile_mock.return_value = True
        valid_mock.return_value = None
        config_mock.return_value = None
        expuser_mock.return_value = ''

        config = Config(['aws_okta_keyman.py', '-c'])
        config.config = '/.config/aws_okta_keyman.yml'
        config.get_config()

        config_mock.assert_has_calls([
            mock.call('/.config/aws_okta_keyman.yml'),
        ])

    @mock.patch('aws_okta_keyman.config.Config.write_config')
    @mock.patch('aws_okta_keyman.config.os.path.expanduser')
    @mock.patch('aws_okta_keyman.config.Config.validate')
    @mock.patch('aws_okta_keyman.config.Config.parse_args')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_get_config_write_mixed_config(self, isfile_mock, _parse_mock,
                                           valid_mock, expuser_mock,
                                           write_mock):
        isfile_mock.return_value = True
        valid_mock.return_value = None
        write_mock.return_value = None
        expuser_mock.return_value = ''

        config = Config(['aws_okta_keyman.py', '-w'])
        config.get_config()
        config.write = './.config/aws_okta_keyman.yml'

        self.assertEqual(config.write, './.config/aws_okta_keyman.yml')
        write_mock.assert_has_calls([
            mock.call(),
        ])

    def test_parse_args_no_req_main(self):
        argv = [
            'aws_okta_keyman.py',
            '-D'
        ]
        config = Config(argv)
        config.parse_args(main_required=False)

        # Should succeed without throwing due to missing args
        self.assertEqual(config.debug, True)

    @mock.patch('argparse.ArgumentParser._print_message', mock.MagicMock())
    def test_parse_args_req_main_missing(self):
        argv = [
            'aws_okta_keyman.py',
            '-D'
        ]
        config = Config(argv)

        # Main required but not passed, should raise
        with self.assertRaises(SystemExit):
            config.parse_args(main_required=True)

    def test_parse_args_req_main_present(self):
        argv = [
            'aws_okta_keyman.py',
            '-a', 'app/id',
            '-o', 'foobar',
            '-u', 'test'
        ]
        config = Config(argv)
        config.parse_args(main_required=True)

        # Should succeed without throwing due to missing args
        self.assertEqual(config.appid, 'app/id')
        self.assertEqual(config.org, 'foobar')
        self.assertEqual(config.username, 'test')

    def test_parse_args_verify_all_parsed_short(self):
        argv = [
            'aws_okta_keyman.py',
            '-a', 'app/id',
            '-ac', 'accountname',
            '-o', 'foobar',
            '-u', 'test',
            '-n', 'profilename',
            '-ro', 'rolename',
            '-c', 'config_file_path',
            '-w', 'write_file_path',
            '-d', 'push',
            '-D', '-r', '-p'
        ]
        config = Config(argv)
        config.parse_args(main_required=True)

        self.assertEqual(config.appid, 'app/id')
        self.assertEqual(config.account, 'accountname')
        self.assertEqual(config.org, 'foobar')
        self.assertEqual(config.username, 'test')
        self.assertEqual(config.name, 'profilename')
        self.assertEqual(config.role, 'rolename')
        self.assertEqual(config.config, 'config_file_path')
        self.assertEqual(config.writepath, 'write_file_path')
        self.assertEqual(config.duo_factor, 'push')
        self.assertEqual(config.debug, True)
        self.assertEqual(config.reup, True)
        self.assertEqual(config.oktapreview, True)

    def test_parse_args_verify_all_parsed_full(self):
        argv = [
            'aws_okta_keyman.py',
            '--account', 'accountname',
            '--appid', 'app/id',
            '--org', 'foobar',
            '--username', 'test',
            '--name', 'profilename',
            '--role', 'rolename',
            '--config', 'config_file_path',
            '--writepath', 'write_file_path',
            '--duo_factor', 'push',
            '--debug', '--reup'
        ]
        config = Config(argv)
        config.parse_args(main_required=True)

        self.assertEqual(config.account, 'accountname')
        self.assertEqual(config.appid, 'app/id')
        self.assertEqual(config.org, 'foobar')
        self.assertEqual(config.username, 'test')
        self.assertEqual(config.name, 'profilename')
        self.assertEqual(config.role, 'rolename')
        self.assertEqual(config.config, 'config_file_path')
        self.assertEqual(config.writepath, 'write_file_path')
        self.assertEqual(config.duo_factor, 'push')
        self.assertEqual(config.debug, True)
        self.assertEqual(config.reup, True)

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml(self, isfile_mock):
        isfile_mock.return_value = True
        yml = ("username: user@example.com\n"
               "org: example\n"
               "appid: app/id\n")

        m = mock.mock_open(read_data=yml)
        with mock.patch('aws_okta_keyman.config.open', m):
            ret = Config.read_yaml('./.config/aws_okta_keyman.yml')

        expected = {
            'username': 'user@example.com', 'org': 'example', 'appid': 'app/id'
        }
        self.assertEqual(ret, expected)

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml_file_missing_no_raise(self, isfile_mock):
        isfile_mock.return_value = False
        ret = Config.read_yaml('./.config/aws_okta_keyman.yml')
        self.assertEqual(ret, {})

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml_file_missing_with_raise(self, isfile_mock):
        isfile_mock.return_value = False
        with self.assertRaises(IOError):
            Config.read_yaml('./.config/aws_okta_keyman.yml',
                             raise_on_error=True)

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml_parse_error_no_raise(self, isfile_mock):
        isfile_mock.return_value = True
        yml = ("username: user@example.com\n"
               "org: example\n"
               "- appid: foo\n")

        m = mock.mock_open(read_data=yml)
        with mock.patch('aws_okta_keyman.config.open', m):
            ret = Config.read_yaml('./.config/aws_okta_keyman.yml')

        self.assertEqual(ret, {})

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml_parse_error_with_raise(self, isfile_mock):
        isfile_mock.return_value = True
        yml = ("username: user@example.com\n"
               "org: example\n"
               "- appid: foo\n")

        m = mock.mock_open(read_data=yml)
        with mock.patch('aws_okta_keyman.config.open', m):
            with self.assertRaises(yaml.parser.ParserError):
                Config.read_yaml('./.config/aws_okta_keyman.yml',
                                 raise_on_error=True)

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml_scan_error_no_raise(self, isfile_mock):
        isfile_mock.return_value = True
        yml = ("username: user@example.com\n"
               "org: example\n"
               "appid app/id\n")

        m = mock.mock_open(read_data=yml)
        with mock.patch('aws_okta_keyman.config.open', m):
            ret = Config.read_yaml('./.config/aws_okta_keyman.yml')

        self.assertEqual(ret, {})

    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_read_yaml_scan_error_with_raise(self, isfile_mock):
        isfile_mock.return_value = True
        yml = ("username: user@example.com\n"
               "org: example\n"
               "appid app/id\n")

        m = mock.mock_open(read_data=yml)
        with mock.patch('aws_okta_keyman.config.open', m):
            with self.assertRaises(yaml.scanner.ScannerError):
                Config.read_yaml('./.config/aws_okta_keyman.yml',
                                 raise_on_error=True)

    def test_parse_config(self):
        config = Config(['aws_okta_keyman.py'])
        config.read_yaml = mock.MagicMock()
        config.read_yaml.return_value = {
            'username': 'user@example.com',
            'org': 'example',
            'appid': 'app/id',
        }

        config.parse_config('./.config/aws_okta_keyman.yml')

        self.assertEqual(config.appid, 'app/id')
        self.assertEqual(config.org, 'example')
        self.assertEqual(config.username, 'user@example.com')

    def test_parse_config_args_preferred(self):
        config = Config(['aws_okta_keyman.py'])
        config.appid = 'mysupercoolapp/id'
        config.org = 'foobar'
        config.username = 'test'
        config.read_yaml = mock.MagicMock()
        config.read_yaml.return_value = {
            'username': 'user@example.com',
            'org': 'example',
            'appid': 'app/id',
        }

        config.parse_config('./.config/aws_okta_keyman.yml')

        # Make sure we're getting the args not the config values
        self.assertEqual(config.appid, 'mysupercoolapp/id')
        self.assertEqual(config.org, 'foobar')
        self.assertEqual(config.username, 'test')

    def test_write_config(self):
        config = Config(['aws_okta_keyman.py'])
        config.clean_config_for_write = mock.MagicMock()
        config_clean = {
            'accounts': [{'name': 'Dev', 'appid': 'A123/123'}],
            'org': 'example',
            'reup': None,
            'username': 'example@example.com',
        }
        config.clean_config_for_write.return_value = config_clean
        config.writepath = './.config/aws_okta_keyman.yml'
        config.username = 'example@example.com'
        config.read_yaml = mock.MagicMock()
        config.read_yaml.return_value = {
            'username': 'user@example.com',
            'org': 'example',
            'appid': 'app/id',
        }

        m = mock.mock_open()
        with mock.patch('aws_okta_keyman.config.open', m):
            config.write_config()

        m.assert_has_calls([
            mock.call(u'./.config/aws_okta_keyman.yml', 'w'),
        ])
        m.assert_has_calls([
            mock.call().write('accounts'),
            mock.call().write(':'),
            mock.call().write('\n'),
            mock.call().write('-'),
            mock.call().write(' '),
            mock.call().write('appid'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('A123/123'),
            mock.call().write('\n'),
            mock.call().write('  '),
            mock.call().write('name'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('Dev'),
            mock.call().write('\n'),
            mock.call().write('org'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('example'),
            mock.call().write('\n'),
            mock.call().write('reup'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('null'),
            mock.call().write('\n'),
            mock.call().write('username'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('example@example.com'),
            mock.call().write('\n'),
            mock.call().flush(),
            mock.call().flush(),
            mock.call().__exit__(None, None, None)
        ])

    def test_write_config_new_file(self):
        config = Config(['aws_okta_keyman.py'])
        config.clean_config_for_write = mock.MagicMock()
        config_clean = {
            'org': 'example',
            'reup': None,
            'username': 'example@example.com',
        }
        config.clean_config_for_write.return_value = config_clean
        config.writepath = './.config/aws_okta_keyman.yml'
        config.username = 'example@example.com'
        config.appid = 'app/id'
        config.org = 'example'
        config.read_yaml = mock.MagicMock()
        config.read_yaml.return_value = {}

        m = mock.mock_open()
        with mock.patch('aws_okta_keyman.config.open', m):
            config.write_config()

        m.assert_has_calls([
            mock.call().write('org'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('example'),
            mock.call().write('\n'),
            mock.call().write('reup'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('null'),
            mock.call().write('\n'),
            mock.call().write('username'),
            mock.call().write(':'),
            mock.call().write(' '),
            mock.call().write('example@example.com'),
            mock.call().write('\n'),
            mock.call().flush(),
            mock.call().flush(),
            mock.call().__exit__(None, None, None)
        ])

    def test_write_config_path_expansion(self):
        config = Config(['aws_okta_keyman.py'])
        config.clean_config_for_write = mock.MagicMock()
        config.clean_config_for_write.return_value = {}
        config.writepath = '~/.config/aws_okta_keyman.yml'
        config.username = 'example@example.com'
        config.appid = 'app/id'
        config.org = 'example'
        config.read_yaml = mock.MagicMock()
        config.read_yaml.return_value = {}

        expected_path = os.path.expanduser(config.writepath)

        m = mock.mock_open()
        with mock.patch('aws_okta_keyman.config.open', m):
            config.write_config()

        m.assert_has_calls([mock.call(expected_path, 'w')])

    @mock.patch('aws_okta_keyman.config.os')
    def test_write_config_path_create_when_missing(self, os_mock):
        config = Config(['aws_okta_keyman.py'])
        config.clean_config_for_write = mock.MagicMock()
        config.clean_config_for_write.return_value = {}
        config.read_yaml = mock.MagicMock()
        config.read_yaml.return_value = {}
        folderpath = '/home/user/.config/'
        os_mock.path.dirname.return_value = folderpath
        os_mock.path.exists.return_value = False

        m = mock.mock_open()
        with mock.patch('aws_okta_keyman.config.open', m):
            config.write_config()

        os_mock.assert_has_calls([
            mock.call.makedirs(folderpath)
        ])

    def test_clean_config_for_write(self):
        config_in = {
            'name': 'foo',
            'appid': 'foo',
            'argv': 'foo',
            'writepath': 'foo',
            'config': 'foo',
            'debug': 'foo',
            'oktapreview': 'foo',
            'accounts': None,
            'shouldstillbehere': 'woohoo',
            'password_reset': True,
            'command': None,
            'update': None
        }
        config_out = {
            'shouldstillbehere': 'woohoo'
        }
        ret = Config.clean_config_for_write(config_in)
        self.assertEqual(ret, config_out)

    def test_clean_config_for_write_with_accounts(self):
        accounts = [
            {'name': 'Account 1', 'appid': 'ABC123'},
            {'name': 'Account 2', 'appid': 'XYZ890'}
        ]
        config_in = {
            'name': 'foo',
            'appid': 'foo',
            'argv': 'foo',
            'writepath': 'foo',
            'config': 'foo',
            'debug': 'foo',
            'oktapreview': 'foo',
            'accounts': accounts,
            'shouldstillbehere': 'woohoo',
            'password_reset': True,
            'command': None,
            'update': None
        }
        config_out = {
            'accounts': accounts,
            'shouldstillbehere': 'woohoo'
        }
        ret = Config.clean_config_for_write(config_in)
        self.assertEqual(ret, config_out)

    @mock.patch('aws_okta_keyman.config.input')
    def test_user_input(self, input_mock):
        input_mock.return_value = ' test '
        self.assertEqual('test', Config.user_input('input test'))

    @mock.patch('aws_okta_keyman.config.getpass')
    @mock.patch('aws_okta_keyman.config.input')
    def test_interactive_config(self, input_mock, getpass_mock):
        input_mock.side_effect = ['org', 'user', 'appid', 'test', '']
        getpass_mock.return_value = 'fakeuser'
        config = Config(['aws_okta_keyman.py'])
        config.write_config = mock.MagicMock()

        config.interactive_config()

        self.assertEqual(config.org, 'org')
        self.assertEqual(config.username, 'user')
        self.assertEqual(config.accounts, [{'name': 'test', 'appid': 'appid'}])
        config.write_config.assert_has_calls([mock.call()])

    @mock.patch('aws_okta_keyman.config.getpass')
    @mock.patch('aws_okta_keyman.config.input')
    def test_interactive_config_auto_user(self, input_mock, getpass_mock):
        input_mock.side_effect = ['org', '', 'appid', 'test', '']
        getpass_mock.return_value = 'fakeuser'
        config = Config(['aws_okta_keyman.py'])
        config.write_config = mock.MagicMock()

        config.interactive_config()

        self.assertEqual(config.username, 'automatic-username')

    @mock.patch('aws_okta_keyman.config.getpass')
    @mock.patch('aws_okta_keyman.config.input')
    def test_interactive_config_auto_account(self, input_mock, _getpass_mock):
        input_mock.side_effect = ['org', 'user', '']
        config = Config(['aws_okta_keyman.py'])
        config.write_config = mock.MagicMock()

        config.interactive_config()

        self.assertEqual(config.accounts, None)

    @mock.patch('aws_okta_keyman.config.getpass')
    @mock.patch('aws_okta_keyman.config.input')
    def test_interactive_config_keyboardexit(self, input_mock, getpass_mock):
        input_mock.side_effect = ['org', 'user', KeyboardInterrupt]
        getpass_mock.return_value = 'fakeuser'
        config = Config(['aws_okta_keyman.py'])
        config.write_config = mock.MagicMock()

        ret = config.interactive_config()
        self.assertEqual(ret, None)
        assert not config.write_config.called
