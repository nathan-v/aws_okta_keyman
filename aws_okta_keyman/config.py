# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright 2018 Nextdoor.com, Inc
# Copyright 2018 Nathan V
"""
Config module is a config object that handles passed-in args and an optional
local config file.
"""
import argparse
import getpass
import logging
import os
import sys
import textwrap

import yaml

from aws_okta_keyman.metadata import __version__

LOG = logging.getLogger(__name__)


class Config:
    """Config class for all tool configuration settings."""

    def __init__(self, argv):
        self.argv = argv
        self.config = None
        self.writepath = '~/.config/aws_okta_keyman.yml'
        self.org = None
        self.accounts = None
        self.username = None
        self.reup = None
        self.debug = None
        self.appid = None
        self.duo_factor = None
        self.name = 'default'
        self.oktapreview = None
        self.password_cache = None
        self.password_reset = None
        self.command = None
        self.screen = None
        self.region = None
        self.duration = None
        self.console = None
        self.update = None
        self.account = None
        self.role = None

        if len(argv) > 1:
            if argv[1] == 'config':
                self.interactive_config()
                sys.exit(0)

    def full_app_url(self):
        """ Retrieve the full Okta app URL. """
        okta_domain = 'okta.com'
        if self.oktapreview:
            okta_domain = 'oktapreview.com'
        full_url = "https://{}.{}/{}".format(
            self.org,
            okta_domain,
            self.appid)
        return full_url

    def set_appid_from_account_id(self, account_id):
        """Take an account ID (list index) and sets the appid based on that."""
        self.appid = self.accounts[account_id]['appid']

    def validate(self):
        """Ensure we have all the settings we need before continuing."""
        if getattr(self, 'org') is None:
            err = ("The parameter org must be provided in the config file "
                   "or as an argument")
            raise ValueError(err)
        duration = getattr(self, 'duration')
        if duration:
            if duration > 43200 or duration < 900:
                err = ("The parameter duration must be between 900 and 43200 "
                       "(15m to 12h).")
                raise ValueError(err)

        if self.region is None:
            self.region = 'us-east-1'

        if self.username is None:
            user = getpass.getuser()
            LOG.info(
                "No username provided; defaulting to current user '{}'".format(
                    user))
            self.username = user
        elif 'automatic-username' in self.username:
            self.username = self.username.replace('automatic-username',
                                                  getpass.getuser())

    def get_config(self):
        """Get the config and set everything up based on the args and/or local
        config file.
        """
        config_file = os.path.expanduser('~') + '/.config/aws_okta_keyman.yml'
        if '-w' in self.argv[1:] or '--writepath' in self.argv[1:]:
            self.parse_args(main_required=False)
            self.write_config()
        elif '-c' in self.argv[1:] or '--config' in self.argv[1:]:
            self.parse_args(main_required=False)
            self.parse_config(self.config)
        elif os.path.isfile(config_file):
            # If we haven't been told to write out the args and no filename is
            # given just use the default path
            self.parse_args(main_required=False)
            self.parse_config(config_file)
        else:
            # No default file, none specified; operate on args only
            self.parse_args()
        self.validate()

    @staticmethod
    def usage_epilog():
        """Epilog string for argparse."""
        epilog = (
            '** Application ID **\n'
            'The ApplicationID is actually a two part piece of the redirect\n'
            'URL that Okta uses when you are logged into the Web UI. If you\n'
            'mouse over the appropriate Application and see a URL that looks\n'
            ' like this. \n'
            '\n'
            '\thttps://foobar.okta.com/home/amazon_aws/0oaciCSo1d8/123?...\n'
            '\n'
            'You would enter in "0oaciCSo1d8/123" as your Application ID.\n'
            '\n'
            '** Configuration File **\n'
            'AWS Okta Keyman can use a config file to pre-configure most of\n'
            'the settings needed for execution. The default location is \n'
            '\'~/.config/aws_okta_keyman.yml\' on Linux/Mac or for Windows \n'
            'it is \'$USERPROFILE\\.config\\aws_okta_keyman.yml\'\n\n'
            'To set up a basic config you can start aws_okta_keyman with '
            'the sole argument \nof config and it will prompt you for the'
            'basic config settings needed to get started\n')
        return epilog

    def parse_args(self, main_required=True):
        """Return a configured ArgumentParser for the CLI options."""
        arg_parser = argparse.ArgumentParser(
            prog=self.argv[0],
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self.usage_epilog(),
            description="AWS Okta Keyman v{}".format(__version__))
        # Remove the default optional arguments section that always shows up.
        # It's not necessary, and can cause confusion.
        #   https://stackoverflow.com/questions/24180527/
        #   argparse-required-arguments-listed-under-optional-arguments
        arg_parser._action_groups.pop()

        optional_args = arg_parser.add_argument_group('Optional arguments')

        if main_required:
            required_args = arg_parser.add_argument_group('Required arguments '
                                                          'or settings')
            self.main_args(required_args, main_required)
        else:
            self.main_args(optional_args)

        self.optional_args(optional_args)

        config = arg_parser.parse_args(args=self.argv[1:])
        config_dict = vars(config)

        for key in config_dict:
            setattr(self, key, config_dict[key])

    @staticmethod
    def main_args(arg_group, required=False):
        """Handle primary arguments for the script; things we must have to run.
        Can be marked as optional if we have a config file.
        """
        arg_group.add_argument('-o', '--org', type=str,
                               help=(
                                   'Okta Organization Name - ie, if your '
                                   'login URL is https://foobar.okta.com, '
                                   'enter in foobar here'
                               ),
                               required=required)

    @staticmethod
    def optional_args(optional_args):
        """Define the always-optional arguments."""
        optional_args.add_argument('-u', '--username', type=str,
                                   help=(
                                     'Okta Login Name - either '
                                     'bob@foobar.com, or just bob works too,'
                                     ' depending on your organization '
                                     'settings. Will use the current user if '
                                     'not specified.'
                                   ))
        optional_args.add_argument('-a', '--appid', type=str, help=(
                                   'The "redirect link" Application ID  - '
                                   'this can be found by mousing over the '
                                   'application in Okta\'s Web UI. See '
                                   'details below for more help.'
                                   ))
        optional_args.add_argument('-V', '--version', action='version',
                                   version=__version__)
        optional_args.add_argument('-D', '--debug', action='store_true',
                                   help=(
                                       'Enable DEBUG logging - note, this is '
                                       'extremely verbose and exposes '
                                       'credentials on the screen so be '
                                       'careful here!'
                                   ),
                                   default=False)
        optional_args.add_argument('-r', '--reup', action='store_true',
                                   help=(
                                       'Automatically re-up the AWS creds '
                                       'before they expire.'
                                   ), default=0)
        optional_args.add_argument('-d', '--duo_factor', type=str,
                                   help=(
                                       'Duo Auth preferred MFA factor. '
                                       'This prevents getting prompted each '
                                       'time Keyman is run.'
                                   ),
                                   default=None,
                                   choices=['web', 'push', 'call', 'passcode'])
        optional_args.add_argument('-n', '--name', type=str,
                                   help='AWS Profile Name', default='default')
        optional_args.add_argument('-c', '--config', type=str,
                                   help='Config File path')
        optional_args.add_argument('-w', '--writepath', type=str,
                                   help='Full config file path to write to',
                                   default='~/.config/aws_okta_keyman.yml')
        optional_args.add_argument('-p', '--oktapreview', action='store_true',
                                   help=(
                                       'Use oktapreview domain. This is '
                                       'useful for testing outside of your '
                                       'production Okta organization.'
                                   ),
                                   default=False)
        optional_args.add_argument('-P', '--password_cache',
                                   action='store_true', help=(
                                       'Use OS keyring to cache your password.'
                                   ),
                                   default=False)
        optional_args.add_argument('-R', '--password_reset',
                                   action='store_true', help=(
                                       'Reset your password in the cache. '
                                       'Use this to update the cached password'
                                       ' if it has changed or is incorrect.'
                                   ),
                                   default=False)
        optional_args.add_argument('-C', '--command', type=str,
                                   help=(
                                        'Command to run with the requested '
                                        'AWS keys provided as environment '
                                        'variables.'
                                    ))
        optional_args.add_argument('-s', '--screen', action='store_true',
                                   help=(
                                       'Print the retrieved key '
                                       'only and do not write to the AWS '
                                       'credentials file.'
                                   ),
                                   default=False)
        optional_args.add_argument('-re', '--region', type=str,
                                   help=(
                                       'AWS region to use for calls. '
                                       'Required for GovCloud.'
                                   ))
        optional_args.add_argument('-du', '--duration', type=int,
                                   help=(
                                       'AWS API Key duration to request. '
                                       'If the supplied value is rejected '
                                       'by AWS the default of 3600s (one '
                                       'hour) will be used.'
                                   ),
                                   default=3600)
        optional_args.add_argument('-co', '--console',
                                   action='store_true', help=(
                                       'Output AWS Console URLs to log in '
                                       'and use the web conle with the '
                                       'selected role..'
                                   ),
                                   default=False)
        optional_args.add_argument('-U', '--update',
                                   action='store_true', help=(
                                       'Check installed Keyman version '
                                       'against latest version in pip and '
                                       'update if the pip version is newer.'
                                   ),
                                   default=False)
        optional_args.add_argument('-ac', '--account', type=str,
                                   help=(
                                       'AWS account if multiple options. '
                                   )),
        optional_args.add_argument('-ro', '--role', type=str,
                                   help=(
                                       'AWS role if multiple options. '
                                   ))

    @staticmethod
    def read_yaml(filename, raise_on_error=False):
        """Read a YAML file and optionally raise if anything goes wrong."""
        config = {}
        try:
            if os.path.isfile(filename):
                config = yaml.load(open(filename, 'r'), Loader=yaml.FullLoader)
                LOG.debug("YAML loaded config: {}".format(config))
            else:
                if raise_on_error:
                    raise IOError("File not found: {}".format(filename))
        except (yaml.parser.ParserError, yaml.scanner.ScannerError):
            LOG.error('Error parsing config file; invalid YAML.')
            if raise_on_error:
                raise
        return config

    def parse_config(self, filename):
        """Parse a configuration file and set the variables from it."""
        config = self.read_yaml(filename, raise_on_error=True)

        for key, value in config.items():
            if not getattr(self, key):  # Only overwrite None not args
                setattr(self, key, value)

    def write_config(self):
        """Use provided arguments and existing config to write an updated
        config file.
        """
        file_path = os.path.expanduser(self.writepath)
        config = self.read_yaml(file_path)

        args_dict = dict(vars(self))

        # Combine file data and user args with user args overwriting
        for key, value in config.items():
            setattr(self, key, value)
        for key in args_dict:
            if args_dict[key] is not None:
                setattr(self, key, args_dict[key])

        config_out = self.clean_config_for_write(dict(vars(self)))

        LOG.debug("YAML being saved: {}".format(config_out))

        file_folder = os.path.dirname(os.path.abspath(file_path))
        if not os.path.exists(file_folder):
            LOG.debug("Creating missin config file folder : {}".format(
                file_folder))
            os.makedirs(file_folder)

        with open(file_path, 'w') as outfile:
            yaml.safe_dump(config_out, outfile, default_flow_style=False)

    @staticmethod
    def clean_config_for_write(config):
        """Remove args we don't want to save to a config file."""
        ignore = ['name', 'appid', 'argv', 'writepath', 'config', 'debug',
                  'oktapreview', 'password_reset', 'command', 'update']
        for var in ignore:
            del config[var]

        if config['accounts'] is None:
            del config['accounts']

        return config

    @staticmethod
    def user_input(text):
        """Wrap input() making testing support of py2 and py3 easier."""
        return input(text).strip()

    def interactive_config(self):
        """ Runs an interactive configuration to make it simpler to create
        the config file. Always uses default path.
        """
        LOG.info('Interactive setup requested')

        try:
            print("\nWhat is your Okta Organization subdomain?")
            print("Example; for https://co.okta.com enter 'co'\n")
            while not self.org:
                self.org = self.user_input('Okta org: ')

            print("\nWhat is your Okta user name?")
            print("If it is {} you can leave this blank.\n".format(
                getpass.getuser()))
            self.username = self.user_input('Username: ')
            if self.username == '':
                self.username = 'automatic-username'

            msg = (
                'Next we can optionally configure your AWS integrations. '
                'This is not required as the AWS integrations can be picked '
                'up automatically from Okta. If you would prefer to list only '
                'specific integrations or prefer to specify the friendly '
                'names yourself you can provide the following information. '
                'You will be prompted to continue providing integration '
                'details until you provide a blank response to the app ID. '
                'If you are unsure how to answer these questions just leave '
                'the app ID blank.')
            print('')
            for line in textwrap.wrap(msg):
                print(line)

            accounts = []
            appid = None
            while not appid == '':
                print("\nWhat is your AWS integration app ID?")
                print("Example; 0oaciCSo1d8/123")
                appid = self.user_input('App ID: ')
                if appid:
                    print("\nPlease provide a friendly name for this app.")
                    name = self.user_input('App ID: ')
                    accounts.append({'name': name, 'appid': appid})

            if accounts:
                self.accounts = accounts

            self.write_config()
            print('')
            LOG.info('Config file written. Please rerun Keyman')
        except KeyboardInterrupt:
            print('')
            LOG.warning('User cancelled configuration; exiting')
