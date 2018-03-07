# Copyright 2018 Nathan V
# Copyright 2018 Nextdoor.com, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

from setuptools import Command
from setuptools import setup
from setuptools import find_packages

from aws_okta_keyman.metadata import __desc__, __version__, __desc_long__

PACKAGE = 'aws_okta_keyman'
DIR = os.path.dirname(os.path.realpath(__file__))


class PycodestyleCommand(Command):
    description = 'Pycodestyle Lint Checks'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # Don't import the pycodestyle module until now because setup.py needs
        # to be able to install pycodestyle if its missing.
        import pycodestyle
        style = pycodestyle.StyleGuide()
        report = style.check_files([PACKAGE])
        if report.total_errors:
            sys.exit("ERROR: pycodestyle failed with {} errors".format(
                report.total_errors))


class PyflakesCommand(Command):
    description = 'Pyflakes Checks'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # Don't import the pyflakes code until now because setup.py needs to be
        # able to install Pyflakes if its missing. This localizes the import to
        # only after the setuptools code has run and verified everything is
        # installed.
        from pyflakes import api
        from pyflakes import reporter

        # Run the Pyflakes check against our package and check its output
        val = api.checkRecursive([PACKAGE], reporter._makeDefaultReporter())
        if val > 0:
            sys.exit("ERROR: Pyflakes failed with exit code {}".format(val))


setup(
    name=PACKAGE,
    version=__version__,
    description=__desc__,
    long_description=__desc_long__,
    author='Nathan V',
    author_email='nathan.v@gmail.com',
    url='https://github.com/nathan-v/aws_okta_keyman',
    download_url="http://pypi.python.org/pypi/{}#downloads".format(PACKAGE),
    license='Apache License, Version 2.0',
    keywords='AWS Okta Keys Auth Authentication MFA Duo',
    packages=find_packages(),
    test_suite='nose.collector',
    tests_require=open("{}/test_requirements.txt".format(DIR)).readlines(),
    setup_requires=[],
    install_requires=open("{}/requirements.txt".format(DIR)).readlines(),
    entry_points={
        'console_scripts': [
            'aws_okta_keyman = aws_okta_keyman.main:entry_point'
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Software Development',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX',
        'Natural Language :: English',
    ],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4',
    cmdclass={
        'pycodestyle': PycodestyleCommand,
        'pyflakes': PyflakesCommand,
    },
)
