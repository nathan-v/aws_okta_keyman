[![Apache](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/nathan-v/aws_okta_keyman/blob/master/LICENSE.txt) [![Python versions](https://img.shields.io/pypi/pyversions/aws-okta-keyman.svg)](https://pypi.python.org/pypi/aws-okta-keyman/0.2.0) [![PyPI version](https://badge.fury.io/py/aws-okta-keyman.svg)](https://badge.fury.io/py/aws-okta-keyman) ![PyPI - Status](https://img.shields.io/pypi/status/aws_okta_keyman) [![Downloads](http://pepy.tech/badge/aws-okta-keyman)](http://pepy.tech/count/aws-okta-keyman)

[![CC GPA](https://codeclimate.com/github/nathan-v/aws_okta_keyman/badges/gpa.svg)](https://codeclimate.com/github/nathan-v/aws_okta_keyman) [![CC Issues](https://codeclimate.com/github/nathan-v/aws_okta_keyman/badges/issue_count.svg)](https://codeclimate.com/github/nathan-v/aws_okta_keyman) [![Coverage Status](https://codecov.io/gh/nathan-v/aws_okta_keyman/branch/master/graph/badge.svg)](https://codecov.io/gh/nathan-v/aws_okta_keyman) ![GitHub issues](https://img.shields.io/github/issues-raw/nathan-v/aws_okta_keyman)

[![Requirements Status](https://requires.io/github/nathan-v/aws_okta_keyman/requirements.svg?branch=master)](https://requires.io/github/nathan-v/aws_okta_keyman/requirements/?branch=master) [![Known Vulnerabilities](https://snyk.io/test/github/nathan-v/aws_okta_keyman/badge.svg)](https://snyk.io/test/github/nathan-v/aws_okta_keyman)

![CircleCI](https://img.shields.io/circleci/build/gh/nathan-v/aws_okta_keyman)

# AWS Okta Keyman

This is a simple command-line tool for logging into Okta and generating
temporary Amazon AWS Credentials. This tool makes it easy and secure for your
developers to generate short-lived, [logged and user-attributed][tracking]
credentials that can be used for any of the Amazon SDK libraries or CLI tools.

## Features

We have support for logging into Okta, optionally handling MFA Authentication,
and then generating new SAML authenticated AWS sessions. This tool has a few core
features that help set it apart from other similar tools that are available.

### Optional MFA Authentication

If you organization requires MFA for the _[initial login into Okta][okta_mfa]_, 
we will automatically detect that requirement during authentication and prompt
the user to complete the Multi Factor Authentication. At this time
application-level MFA is not supported.

In particular, there is support for standard passcode based auth, as well as
support for [Okta Verify with Push][okta_verify] and [Duo Auth][duo_auth]. If both
are available, Okta Verify with Push will be prioritized and a push notification is
_automatically sent to the user_. If the user declines the validation, then
optionally the Passcode can be entered in manually.

For Duo Auth Duo wants you to use a web page to load their iframe to pick your factor
and then move forward from there. That is one option and the one most likely to keep
working. This tool now also has an alternative browserless option that attempts to
use Duo for MFA without a browser. This may eventually be stopped/prevented by Duo
but makes this tool work on remote servers or in any other case where you may not
be able to use a browser.

#### Supported MFA Solutions

* Okta Verify
* Duo Auth (push, call, or OTP)
* Okta OTP
* Google Auth OTP
* SMS OTP
* Call OTP
* Question/Answer

Windows Hello, U2F, email, and physical token (RSA, Symantec) are not supported
at this time.

### Multiple AWS Roles

AWS Okta Keyman supports multiple AWS roles when configured. The user is prompted to
select the role they wish to use before the temporary keys are generated. An example
of this is shown here:

    17:10:21   (WARNING) Multiple AWS roles found; please select one
    [0] Role: arn:aws:iam::012345678910:role/admin_noiam
    [1] Role: arn:aws:iam::012345678910:role/readonly
    [2] Role: arn:aws:iam::012345678910:role/admin_full
    Select a role from above: 2
    17:10:22   (INFO) Assuming role: arn:aws:iam::012345678910:role/admin_full


### Re-Up Mode .. Automatic Credential Re-Generation

Amazon IAM only supports Federated Login sessions that last up to *1 hour*. For
developers, it can be painful to re-authenticate every hour during your work
day. This is made much worse if your organization requires MFA on each login.

You may run the AWS Okta Keyman in "reup" mode to get around this. The tool
will continue to run in a sleep loop periodically reaching out to Okta,
generating a new SAML Assertion, and then generating updated Amazon AWS
credentials. This can run for as long as your Okta administrator has allowed
your Login Session to be - often a full work day.

See the `--reup` commandline option for help here!


### AWS Accounts from Okta

As of v0.5.1 AWS Okta Keyman can pull the AWS Accounts that have been assigned
from Okta itself which means the app ID value no longer needs to be provided in
the command line or in the config file. A config file can still optionally be used
to ensure account names or order if preferred.

### Automatic Username

As of v0.5.1 AWS Okta Keyman will use the current user as the username for Okta
authentication if no username has been provided.


### Config file .. predefined settings for you or your org

The config file, which defaults to `~/.config/aws_okta_keyman.yml`, allows you to
pre-set things like your username, Okta organization name (subdomain), and AWS accounts
and App IDs to make this script simpler to use. This also supports username assumption
based on the current user when the username or email is configured as
`automatic-username` if usernames only are an option or
`automatic-username@example.com` if you need full emails. Arguments will always
be preferred to the config file so you can override what's in the config file
as needed on each run of the tool.

Example config file:

    username: automatic-username@example.com
    org: example
    accounts:
      - name: Test
        appid: exampleAppIDFromOkta/123
      - name: Dev
        appid: exampleAppIDFromOkta/234
      - name: Prod
        appid: exampleAppIDFromOkta/345

When used you'll get a similar interface to AWS Role selection but for your AWS
accounts:

    $ aws_okta_keyman
    16:56:47   (INFO) AWS Okta Keyman v0.3.0
    16:56:47   (WARNING) No app ID provided; please select from available AWS accounts
    [0] Account: Test
    [1] Account: Dev
    [2] Account: Prod
    Select an account from above: 0
    16:56:49   (INFO) Using account: Test / exampleAppIDFromOkta/123

### Interactive Configuration

For interactive configuration and creation of the config file you can start the tool with just config as a parameter and you will be propted to provide the basic information needed to get started.

`aws_okta_keyman config`

### Python Versions

Python 2.7.4+ and Python 3.5.0+ are supported

## Usage

### Client Setup

Before you can install this tool you need to have a working Python installation with pip.
If you're not sure if you have this a good place to start would be the [Python Beginner's Guide](https://wiki.python.org/moin/BeginnersGuide/Download) .

Once your Python environment is configured simply run `pip install aws-okta-keyman` to install the tool.

### Running AWS Okta Keyman

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

### Okta Setup
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

## Developer Info

See CONTRIBUTING.md for more information on contributing to this project.
    
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
[duo_auth]: https://duo.com/
