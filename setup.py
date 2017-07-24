# Copyright 2017 Nextdoor.com, Inc.
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

from nd_okta_auth.metadata import __desc__, __version__

PACKAGE = 'nd_okta_auth'
DIR = os.path.dirname(os.path.realpath(__file__))


class Pep8Command(Command):
    description = 'Pep8 Lint Checks'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        # Don't import the pep8 module until now because setup.py needs to be
        # able to install Pep8 if its missing.
        import pep8
        pep8style = pep8.StyleGuide(parse_argv=True, config_file='pep8.cfg')
        report = pep8style.check_files([PACKAGE])
        if report.total_errors:
            sys.exit('ERROR: Pep8 failed with exit %d errors' %
                     report.total_errors)


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
            sys.exit('ERROR: Pyflakes failed with exit code %d' % val)


setup(
    name=PACKAGE,
    version=__version__,
    description=__desc__,
    long_description=open('%s/README.md' % DIR).read(),
    author='Nextdoor Engineering',
    author_email='eng@nextdoor.com',
    url='https://github.com/Nextdoor/nd_okta_auth',
    download_url='http://pypi.python.org/pypi/%s#downloads' % PACKAGE,
    license='Apache License, Version 2.0',
    keywords='apache',
    packages=find_packages(),
    test_suite='nose.collector',
    tests_require=open('%s/requirements.test.txt' % DIR).readlines(),
    setup_requires=[],
    install_requires=open('%s/requirements.txt' % DIR).readlines(),
    entry_points={
        'console_scripts': [
            'nd_okta_auth = nd_okta_auth.main:entry_point'
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Software Development',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Operating System :: POSIX',
        'Natural Language :: English',
    ],
    cmdclass={
        'pep8': Pep8Command,
        'pyflakes': PyflakesCommand,
    },
)
