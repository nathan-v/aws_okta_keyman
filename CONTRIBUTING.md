# Contributing to AWS Okta Keyman

## Code Style

This project uses `pycodestyle` and `pyflakes` to check for style errors. Please
use these tools to check changes before submitting PRs. Both can be run with setup.py
as shown below.

    $ python setup.py pyflakes
    $ python setup.py pycodestyle

## Python Versions

Python 2.7.4+ and Python 3.5.0+ are supported. As much Python version compatibility as
possible will be maintained.

## Testing

### Unit tests

Unit tests have been written using nose and should be included with every PR. If the PR
is a bug fix please include a regression test as well.

### Running Tests

The command below will run all of the unit tests for the package with lots of details 
and will spit out the current code coverage numbers. Code coverage for this project is
high and the intent is that it stays that way.

    $ pytest

### Tox

Optionally Tox can be used to test multiple Python versions at once. Currently `tox.ini`
is set to test all of the supported Python major versions.

## Developer Setup

Dev environment setup is easy. You need a supported version of Python, git, and
virtualenv installed.

    $ git clone https://github.com/nathan-v/aws_okta_keyman.git
    $ cd aws_okta_keyman
    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install -r requirements.txt
    $ pip install -r test_requirements.txt
