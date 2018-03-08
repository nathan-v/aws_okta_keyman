[![Apache](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/nathan-v/aws_okta_keyman/blob/master/LICENSE.txt) [![PyPI version](https://badge.fury.io/py/aws-okta-keyman.svg)](https://badge.fury.io/py/aws-okta-keyman) [![Python versions](https://img.shields.io/pypi/pyversions/aws-okta-keyman.svg?style=flat-square)](https://pypi.python.org/pypi/aws-okta-keyman/0.2.0)

[![CircleCI](https://circleci.com/gh/nathan-v/aws_okta_keyman.svg?style=svg&circle-token=93e91f099440edc9f62378bb3f056af8b0841231)](https://circleci.com/gh/nathan-v/aws_okta_keyman) [![CC GPA](https://codeclimate.com/github/nathan-v/aws_okta_keyman/badges/gpa.svg)](https://codeclimate.com/github/nathan-v/aws_okta_keyman) [![CC Issues](https://codeclimate.com/github/nathan-v/aws_okta_keyman/badges/issue_count.svg)](https://codeclimate.com/github/nathan-v/aws_okta_keyman) [![Coverage Status](https://coveralls.io/repos/github/nathan-v/aws_okta_keyman/badge.svg?branch=master)](https://coveralls.io/github/nathan-v/aws_okta_keyman?branch=master)

# AWS Okta Keyman

This is a simple command-line tool for logging into Okta and generating
temporary Amazon AWS Credentials. This tool makes it easy and secure for your
developers to generate short-lived, [logged and user-attributed][tracking]
credentials that can be used for any of the Amazon SDK libraries or CLI tools.

# Features

We have support for logging into Okta, optionally handling MFA Authentication,
and then generating new SAML authenticated AWS sessions. In paritcular, this
tool has a few core features.

## Optional MFA Authentication

If you organization requires MFA for the _[initial login into Okta][okta_mfa]_, 
we will automatically detect that requirement during authentication and prompt
the user to complete the Multi Factor Authentication.

In paritcular, there is support for standard passcode based auth, as well as
support for [Okta Verify with Push][okta_verify] and Duo Auth. If both are available,
Okta Verify with Push will be prioritized and a push notification is
_automatically sent to the user_. If the user declines the validation, then
optionally the Passcode can be entered in manually.

In the case of Duo Auth a web page is opened (served locally) for the user to
interact with Duo and select their preferred authentication method. Once Duo is
successful the user may close the browser or tab.

## Multiple AWS Roles

AWS Okta Keyman supports multiple AWS roles when configued. The user is prompted to
select the role they wish to use before the temporary keys are generated. An example
of this is shown here:

    17:10:21   (WARNING) Multiple AWS roles found; please select one
    [0] Role: arn:aws:iam::012345678910:role/admin_noiam
    [1] Role: arn:aws:iam::012345678910:role/readonly
    [2] Role: arn:aws:iam::012345678910:role/admin_full
    Select a role from above: 2
    17:10:22   (INFO) Assuming role: arn:aws:iam::012345678910:role/admin_full


## Re-Up Mode .. Automatic Credential Re-Generation

Amazon IAM only supports Federated Login sessions that last up to *1 hour*. For
developers, it can be painful to re-authenticate every hour during your work
day. This is made much worse if your organization requires MFA on each login.

You may run the AWS Okta Keyman in "reup" mode to get around this. The tool
will continue to run in a sleep loop periodically reaching out to Okta,
generating a new SAML Assertion, and then generating updated Amazon AWS
credentials. This can run for as long as your Okta administrator has allowed
your Login Session to be - often a full work day.

See the `--reup` commandline option for help here!

# Usage

For detailed usage instructions, see the `--help` commandline argument.

Typical usage:

    $ aws_okta_keyman -a <application id> -o <your org name> -u <your username>
    08:27:44   (INFO) AWS Okta Keyman v0.2.0
    Password: 
    08:27:48   (WARNING) Okta Verify Push being sent...
    08:27:48   (INFO) Waiting for Okta Verification...
    ...
    08:28:09   (INFO) Waiting for Okta Verification...
    08:28:10   (INFO) Successfully authed Nathan V
    08:28:10   (INFO) Getting SAML Assertion from foobar
    08:28:11   (INFO) Found credentials in shared credentials file: ~/.aws/credentials
    08:28:11   (INFO) Wrote profile "default" to /Users/nathan-v/.aws/credentials
    08:28:11   (INFO) Session expires at 2017-07-24 16:28:13+00:00
    $

## Okta Setup
Before you can use this tool, your Okta administrator needs to set up
[Amazon/Okta integration][okta_aws_guide] using SAML roles.

## Background
This is a hard fork of [nd_okta_auth][nd_okta_auth] by [Nextdoor.com, Inc.][nextdoorinc].
I decided to move ahead this way as I wanted to be able to move quickly and add
features independently of the existing implementation. A big thank you to @diranged
for the original work that this comes from.

The original code is heavily based on the previous work done by
[ThoughtWorksInc][thoughtworksinc] on their [OktaAuth][oktaauth] and [AWS Role
Credentials][aws_role_credentials] tools.

# Developer Setup

If you are interested in working on the codebase, setting up your development
environment is quick and easy.

    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install -r requirements.txt
    $ pip install -r test_requirements.txt
    
## Python Versions

Python 2.7.1+ and Python 3.5.0+ are supported

## Running Tests

    $ nosetests -vv --with-coverage --cover-erase --cover-package=aws_okta_keyman

## Code Style

This project uses `pycodestyle` and `pyflakes` to check for style errors. Please
use these tools to check changes before submitting PRs.

## License

Copyright 2018 Nathan V

Copyright 2018 Nextdoor.com, Inc

Licensed under the Apache License, Version 2.0. See LICENSE.txt file for details.

Some code in `aws_okta_keyman/okta.py`, `aws_okta_keyman/aws.py`,
`aws_okta_keyman/aws_saml.py`, and `aws_okta_keyman/test/aws_saml_test.py` is 
distributed under MIT license. See the source files for details. A copy of the
license is in the LICENSE_MIT.txt file.

[nd_okta_auth]: https://github.com/Nextdoor/nd_okta_auth
[nextdoorinc]: https://github.com/Nextdoor
[oktaauth]: https://github.com/ThoughtWorksInc/oktaauth
[aws_role_credentials]: https://github.com/ThoughtWorksInc/aws_role_credentials
[thoughtworksinc]: https://github.com/ThoughtWorksInc
[tracking]: https://aws.amazon.com/blogs/security/how-to-easily-identify-your-federated-users-by-using-aws-cloudtrail/
[okta_aws_guide]: https://support.okta.com/help/servlet/fileField?retURL=%2Fhelp%2Farticles%2FKnowledge_Article%2FAmazon-Web-Services-and-Okta-Integration-Guide&entityId=ka0F0000000MeyyIAC&field=File_Attachment__Body__s
[okta_mfa]: https://www.okta.com/products/adaptive-multi-factor-authentication/
[okta_verify]: https://www.okta.com/blog/tag/okta-verify-with-push/
[aws_saml]: http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
