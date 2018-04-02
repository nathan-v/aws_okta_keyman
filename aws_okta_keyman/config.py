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

import yaml
from aws_okta_keyman.metadata import __version__

LOG = logging.getLogger(__name__)


class Config:
    """Config class for all tool configuration settings."""

    def __init__(self, argv):
        self.argv = argv
        self.config = None
        self.writepath = None
        self.org = None
        self.accounts = None
        self.username = None
        self.reup = None
        self.debug = None
        self.appid = None
        self.name = 'default'

    def set_appid_from_account_id(self, account_id):
        """Take an account ID (list index) and sets the appid based on that."""
        self.appid = self.accounts[account_id]['appid']

    def validate(self):
        """Ensure we have all the settings we need before continuing."""
        if self.appid is None:
            if not self.accounts:
                raise ValueError('The appid parameter is required if accounts '
                                 'have not been set in the config file.')
        required = ['org', 'username']
        for arg in required:
            if getattr(self, arg) is None:
                err = ("The parameter {} must be provided in the config file "
                       "or as an argument".format(arg))
                raise ValueError(err)

        self.username = self.username.replace('automatic-username',
                                              getpass.getuser())

    def get_config(self):
        """Get the config and set everything up based on the args and/or local
        config file.
        """
        file = os.path.expanduser('~') + '/.config/aws_okta_keyman.yml'
        if '-w' in self.argv[1:] or '--writepath' in self.argv[1:]:
            self.parse_args(main_required=False)
            self.write_config()
        elif '-c' in self.argv[1:] or '--config' in self.argv[1:]:
            self.parse_args(main_required=False)
            self.parse_config(self.config)
        elif os.path.isfile(file):
            # If we haven't been told to write out the args and no filename is
            # given just use the default path
            self.parse_args(main_required=False)
            self.parse_config(file)
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
            'it is \'$USERPROFILE\\.config\\aws_okta_keyman.yml\'\n')
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
        arg_group.add_argument('-u', '--username', type=str,
                               help=(
                                   'Okta Login Name - either '
                                   'bob@foobar.com, or just bob works too,'
                                   ' depending on your organization '
                                   'settings.'
                               ),
                               required=required)
        arg_group.add_argument('-a', '--appid', type=str,
                               help=(
                                   'The "redirect link" Application ID  - '
                                   'this can be found by mousing over the '
                                   'application in Okta\'s Web UI. See '
                                   'details below for more help.'
                               ),
                               required=required)

    @staticmethod
    def optional_args(optional_args):
        """Define the always-optional arguments."""
        optional_args.add_argument('-V', '--version', action='version',
                                   version=__version__)
        optional_args.add_argument('-D', '--debug', action='store_true',
                                   help=(
                                       'Enable DEBUG logging - note, this is '
                                       'extremely verbose and exposes '
                                       'credentials so be careful here!'
                                   ),
                                   default=False)
        optional_args.add_argument('-r', '--reup', action='store_true',
                                   help=(
                                       'Automatically re-up the AWS creds '
                                       'before they expire.'
                                   ), default=0)
        optional_args.add_argument('-n', '--name', type=str,
                                   help='AWS Profile Name', default='default')
        optional_args.add_argument('-c', '--config', type=str,
                                   help='Config File path')
        optional_args.add_argument('-w', '--writepath', type=str,
                                   help='Full config file path to write to',
                                   default='~/.config/aws_okta_keyman.yml')

    def parse_config(self, filename):
        """Parse a configuration file and set the variables from it."""
        if os.path.isfile(filename):
            config = yaml.load(open(filename, 'r'))
        else:
            raise IOError("File not found: {}".format(filename))

        LOG.debug("YAML loaded config: {}".format(config))

        for key, value in config.items():
            if getattr(self, key) is None:  # Only overwrite None not args
                setattr(self, key, value)

    def write_config(self):
        """Use provided arguments and existing config to write an updated
        config file.
        """
        file_path = os.path.expanduser(self.writepath)
        if os.path.isfile(file_path):
            config = yaml.load(open(file_path, 'r'))
        else:
            config = {}

        LOG.debug("YAML loaded config: {}".format(config))

        args_dict = dict(vars(self))

        # Combine file data and user args with user args overwriting
        for key, value in config.items():
            setattr(self, key, value)
        for key in args_dict:
            if args_dict[key] is not None:
                setattr(self, key, args_dict[key])

        config = dict(vars(self))
        # Remove args we don't want to save to a config file
        for var in ['name', 'appid', 'argv', 'writepath', 'config', 'debug']:
            del config[var]

        if config['accounts'] is None:
            del config['accounts']

        LOG.debug("YAML being saved: {}".format(config))

        with open(file_path, 'w') as outfile:
            yaml.safe_dump(config, outfile, default_flow_style=False)
