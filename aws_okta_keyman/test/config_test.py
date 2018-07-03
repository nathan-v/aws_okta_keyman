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

    @mock.patch('aws_okta_keyman.config.Config.parse_config')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_set_appid_from_account_id(self, isfile_mock, parse_mock):
        isfile_mock.return_value = True
        parse_mock.return_value = None
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.set_appid_from_account_id(0)
        self.assertEquals(config.appid, 'A123')

    def test_validate_good_with_accounts(self):
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.org = 'example'
        config.username = 'user@example.com'
        self.assertEquals(config.validate(), None)

    def test_validate_good_with_appid(self):
        config = Config(['aws_okta_keyman.py'])
        config.appid = 'A123'
        config.org = 'example'
        config.username = 'user@example.com'
        self.assertEquals(config.validate(), None)

    def test_validate_missing_username(self):
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.org = 'example'
        with self.assertRaises(ValueError):
            config.validate()

    def test_validate_missing_org(self):
        config = Config(['aws_okta_keyman.py'])
        config.accounts = [{'appid': 'A123'}]
        config.username = 'user@example.com'
        with self.assertRaises(ValueError):
            config.validate()

    def test_validate_missing_appid_and_accounts(self):
        config = Config(['aws_okta_keyman.py'])
        config.username = 'user@example.com'
        config.org = 'example'
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

    @mock.patch('aws_okta_keyman.config.os.path.expanduser')
    @mock.patch('aws_okta_keyman.config.Config.parse_config')
    @mock.patch('aws_okta_keyman.config.Config.validate')
    @mock.patch('aws_okta_keyman.config.Config.parse_args')
    @mock.patch('aws_okta_keyman.config.os.path.isfile')
    def test_get_config_specified_config_only(self, isfile_mock, parse_mock,
                                              valid_mock, config_mock,
                                              expuser_mock):
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
    def test_get_config_write_mixed_config(self, isfile_mock, parse_mock,
                                           valid_mock, expuser_mock,
                                           write_mock):
        isfile_mock.return_value = True
        valid_mock.return_value = None
        write_mock.return_value = None
        expuser_mock.return_value = ''

        config = Config(['aws_okta_keyman.py', '-w'])
        config.get_config()
        config.write = './.config/aws_okta_keyman.yml'

        self.assertEquals(config.write, './.config/aws_okta_keyman.yml')
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
        self.assertEquals(config.debug, True)

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
        self.assertEquals(config.appid, 'app/id')
        self.assertEquals(config.org, 'foobar')
        self.assertEquals(config.username, 'test')

    def test_parse_args_verify_all_parsed_short(self):
        argv = [
            'aws_okta_keyman.py',
            '-a', 'app/id',
            '-o', 'foobar',
            '-u', 'test',
            '-n', 'profilename',
            '-c', 'config_file_path',
            '-w', 'write_file_path',
            '-R', 'us-west-2',
            '-D', '-r', '-p'
        ]
        config = Config(argv)
        config.parse_args(main_required=True)

        self.assertEquals(config.appid, 'app/id')
        self.assertEquals(config.org, 'foobar')
        self.assertEquals(config.username, 'test')
        self.assertEquals(config.name, 'profilename')
        self.assertEquals(config.config, 'config_file_path')
        self.assertEquals(config.writepath, 'write_file_path')
        self.assertEquals(config.region, 'us-west-2')
        self.assertEquals(config.debug, True)
        self.assertEquals(config.reup, True)
        self.assertEquals(config.oktapreview, True)

    def test_parse_args_verify_all_parsed_full(self):
        argv = [
            'aws_okta_keyman.py',
            '--appid', 'app/id',
            '--org', 'foobar',
            '--username', 'test',
            '--name', 'profilename',
            '--config', 'config_file_path',
            '--writepath', 'write_file_path',
            '--region', 'us-west-2',
            '--debug', '--reup'
        ]
        config = Config(argv)
        config.parse_args(main_required=True)

        self.assertEquals(config.appid, 'app/id')
        self.assertEquals(config.org, 'foobar')
        self.assertEquals(config.username, 'test')
        self.assertEquals(config.name, 'profilename')
        self.assertEquals(config.config, 'config_file_path')
        self.assertEquals(config.writepath, 'write_file_path')
        self.assertEquals(config.region, 'us-west-2')
        self.assertEquals(config.debug, True)
        self.assertEquals(config.reup, True)

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

        self.assertEquals(config.appid, 'app/id')
        self.assertEquals(config.org, 'example')
        self.assertEquals(config.username, 'user@example.com')

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
        self.assertEquals(config.appid, 'mysupercoolapp/id')
        self.assertEquals(config.org, 'foobar')
        self.assertEquals(config.username, 'test')

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
            'shouldstillbehere': 'woohoo'
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
            'shouldstillbehere': 'woohoo'
        }
        config_out = {
            'accounts': accounts,
            'shouldstillbehere': 'woohoo'
        }
        ret = Config.clean_config_for_write(config_in)
        self.assertEqual(ret, config_out)
