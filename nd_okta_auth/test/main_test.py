import unittest
import mock

from nd_okta_auth import main


class MainTest(unittest.TestCase):

    @mock.patch('nd_okta_auth.okta.Okta')
    @mock.patch('argparse.ArgumentParser')
    @mock.patch('getpass.getpass')
    def test_entry_point(self, pass_mock, arg_mock, okta_mock):
        # Mock out the password getter and return a simple passwordj
        pass_mock.return_value = 'test_password'

        # Just mock out the entire Okta object, we won't really instantiate it
        okta_mock.return_value = mock.MagicMock()

        # Mock out the arguments that were passed in
        fake_parser = mock.MagicMock(name='fake_parser')
        fake_parser.parse_args().server = 'server'
        fake_parser.parse_args().username = 'username'
        arg_mock.return_value = fake_parser

        main.main('test')

        okta_mock.assert_called_with('server', 'username', 'test_password')
