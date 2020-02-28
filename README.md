[![Apache](https://img.shields.io/badge/license-Apache-blue.svg)](https://github.com/nathan-v/aws_okta_keyman/blob/master/LICENSE.txt) [![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnathan-v%2Faws_okta_keyman.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnathan-v%2Faws_okta_keyman?ref=badge_shield) [![Python versions](https://img.shields.io/pypi/pyversions/aws-okta-keyman.svg)](https://pypi.python.org/pypi/aws-okta-keyman/) ![PyPI - Implementation](https://img.shields.io/pypi/implementation/aws-okta-keyman) [![Downloads](http://pepy.tech/badge/aws-okta-keyman)](http://pepy.tech/count/aws-okta-keyman)

[![Requirements Status](https://pyup.io/repos/github/nathan-v/aws_okta_keyman/shield.svg?t=1580777582434)](https://pyup.io/repos/github/nathan-v/aws_okta_keyman/) ![Code Climate maintainability](https://img.shields.io/codeclimate/maintainability/nathan-v/aws_okta_keyman)  ![Code Climate issues](https://img.shields.io/codeclimate/issues/nathan-v/aws_okta_keyman) ![Code Climate technical debt](https://img.shields.io/codeclimate/tech-debt/nathan-v/aws_okta_keyman) ![Codecov](https://img.shields.io/codecov/c/gh/nathan-v/aws_okta_keyman) ![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/nathan-v/aws_okta_keyman)

![GitHub release (latest by date)](https://img.shields.io/github/v/release/nathan-v/aws_okta_keyman) ![GitHub Release Date](https://img.shields.io/github/release-date/nathan-v/aws_okta_keyman) [![PyPI version](https://badge.fury.io/py/aws-okta-keyman.svg)](https://badge.fury.io/py/aws-okta-keyman) ![PyPI - Status](https://img.shields.io/pypi/status/aws_okta_keyman) [![Sourcegraph](https://img.shields.io/badge/view%20on-Sourcegraph-brightgreen.svg?logo=sourcegraph)](https://sourcegraph.com/github.com/nathan-v/aws_okta_keyman)

[![CircleCI](https://img.shields.io/circleci/build/gh/nathan-v/aws_okta_keyman/master?label=master&logo=circleci)](https://circleci.com/gh/nathan-v/aws_okta_keyman/tree/master) ![GitHub last commit](https://img.shields.io/github/last-commit/nathan-v/aws_okta_keyman)

# AWS Okta Keyman
This is a simple command-line tool for logging into Okta and generating
temporary Amazon AWS Credentials. This tool makes it easy and secure to
generate short-lived, [logged and user-attributed][tracking] credentials that can be
used for any of the Amazon SDK libraries or CLI tools.

## Features
Key features listed here. Keep scrolling for more details.

* MFA support
* Multiple AWS role support
* Automatic reup/refresh mode
* Dynamic AWS/Okta integration list
* Automatic username selection
* Okta password caching
* Command wrapping
* Screen/shell only output
* GovCloud support
* Adjustable key lifetime
* Console login URLs
* Config files
* Interactive config generation
* Installation via pip and Homebrew
* Linux, Windows, and OSX support

Benefits vs other similar tools:

* Runs without external dependencies; no servers or lambdas required
* No API keys required; just your Okta username and password
* No analytics or metrics collection; this tool does _not_ call home in any way
* Open source distributed as source; you can see what you're running
* Wide Python version support; works on Python 2.7.4+ and 3.5.0+.

### Optional MFA Authentication
If you organization or integration requires MFA  we will automatically detect that
requirement during authentication and prompt the user to complete the
Multi Factor Authentication.

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
* Duo Auth (push, call, or OTP via CLI)
* Duo Auth (push, call, or OTP via web browser)
* Okta OTP
* Google Auth OTP
* SMS OTP
* Call OTP
* Question/Answer

Windows Hello, U2F, email, and physical token (RSA, Symantec) are not supported
at this time.

### Multiple AWS Roles
AWS Okta Keyman supports multiple AWS roles when configured. The user is prompted to
select the role they wish to use before the temporary keys are generated.

### Re-Up Mode .. Automatic Credential Re-Generation
Amazon IAM defaults to Federated Login sessions that last up to *1 hour*. For
developers, it can be painful to re-authenticate every hour during your work
day. This is made much worse if your organization requires MFA on each login.

You may run the AWS Okta Keyman in "reup" mode to get around this. The tool
will continue to run in a sleep loop periodically reaching out to Okta,
generating a new SAML Assertion, and then generating updated Amazon AWS
credentials. This can run for as long as your Okta administrator has allowed
your Login Session to be - often a full work day.

In the case of application-level MFA you will be prompted every 50 minutes or
so to complete the MFA again.

See the `--reup` commandline option for help here!

### AWS Accounts from Okta
AWS Okta Keyman can pull the AWS Accounts that have been assigned from Okta
itself which means the app ID value no longer needs to be provided in the
command line or in the config file. A config file can still optionally be used
to ensure account names or order if preferred. This means with no configuration
saved you only need to provide your organization.

### Automatic Username
AWS Okta Keyman will use the current user as the username for Okta
authentication if no username has been provided.

### Keyring Password Cache
AWS Okta Keyman can use your local keyring to store your Okta password to allow you to
run the tool repeatedly without needing to type your password in each time. For details on how this
is accomplished check out [keyring][keyring].

```text
aws_okta_keyman -P    # Enable the password cache
aws_okta_keyman -R    # Reset the cached password in case of mistaken entry or password change
```

### Command Wrapping
Command wrapping provides a simple way to execute any command you would like directly from
Keyman where the AWS access key environment variables will be provided when starting the
command. An example of this is provided here:

```text
$ aws_okta_keyman --command "echo \$AWS_ACCESS_KEY_ID"

----snip----

14:07:17   (INFO) Wrote profile "default" to /home/nathan/.aws/credentials 💾
14:07:17   (INFO) Current time is 2020-01-10 22:07:17.027964
14:07:17   (INFO) Session expires at 2020-01-10 23:07:16+00:00 ⏳
14:07:17   (INFO) Running requested command...


AXXXXXXXXXXXXXXXXXXX

```

### Screen-only Key Output
Screen-only output for cases were the key needs to be copied
elsewhere for use. This makes using the temporary keys in other apps simpler and easier.
They will not be written out to the AWS credentials file when this option is specified.

```text
$ aws_okta_keyman --screen

----snip----

14:14:04   (INFO) Assuming role: arn:aws:iam::1234567890:role/Admin
14:14:04   (INFO) AWS Credentials: 

AWS_ACCESS_KEY_ID = AXXXXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_SESSION_TOKEN = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

14:14:04 (INFO) All done! 👍
```

### GovCloud Support
AWS Okta Keyman now works with AWS GovCloud. Use the `--region` command-line option
to specify the AWS region to get the keys from.

### Preferred Key Duration
You can set a key lifetime other than the default 1 hour by setting `--duration` when calling Keyman.
If AWS rejects the request for a longer duration the default 1 hour will be used instead. You can request
key durations from a minimum of 15 minutes (900 seconds) or up to 12 hours (43200 seconds). These
limits are enforced by AWS and are not a limitation of Keyman.

### AWS Console Logins
AWS Console login links can optionally be generated when yo request keys with Keyman. 
The console login link will be output on the screen for you to use. Just provide the `--console`
parameter when running Keyman.

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

```yaml
username: automatic-username@example.com
org: example
accounts:
  - name: Dev
    appid: exampleAppIDFromOkta/234
  - name: Prod
    appid: exampleAppIDFromOkta/345
```

When used you'll get a similar interface to AWS Role selection but for your AWS
accounts.

### Interactive Configuration
For interactive configuration and creation of the config file you can start the tool with just config as a parameter and you will be propted to provide the basic information needed to get started. An example of this is shown here:

```text
$ aws_okta_keyman config
14:21:41   (INFO) AWS Okta Keyman 🔐 v0.7.0
14:21:41   (INFO) Interactive setup requested

What is your Okta Organization subdomain?
Example; for https://co.okta.com enter 'co'

Okta org: example

What is your Okta user name?
If it is nathan you can leave this blank.

Username: nathan.v

Next we can optionally configure your AWS integrations. This is not
required as the AWS integrations can be picked up automatically from
Okta. If you would prefer to list only specific integrations or prefer
to specify the friendly names yourself you can provide the following
information. You will be prompted to continue providing integration
details until you provide a blank response to the app ID. If you are
unsure how to answer these questions just leave the app ID blank.

What is your AWS integration app ID?
Example; 0oaciCSo1d8/123
App ID: 0oaciCSo1d8/123

Please provide a friendly name for this app.
App ID: AWS Prod

What is your AWS integration app ID?
Example; 0oaciCSo1d8/123
App ID:

14:21:58   (INFO) Config file written. Please rerun Keyman
```

## Python Versions
Python 2.7.4+ and Python 3.5.0+ are supported.

Support for older Python versions will be maintained as long as is reasonable.
Before support is removed a reminder/warning will be provided.

## Usage
### Client Setup
#### Mac OS Installation
`brew tap nathan-v/aws-okta-keyman` and then `brew install aws_okta_keyman`.

Or install via URL (which will not receive updates):

```
brew install https://raw.githubusercontent.com/nathan-v/homebrew-aws-okta-keyman/master/Formula/aws_okta_keyman.rb
```

#### Linux or Windows Installation
Before you can install this tool you need to have a working Python installation with pip.
If you're not sure if you have this a good place to start would be the [Python Beginner's Guide](pythonbeginner) .

Once your Python environment is configured simply run `pip install aws-okta-keyman` to install the tool.

### Running AWS Okta Keyman
For detailed usage instructions, see the `--help` commandline argument.

Typical usage:

```text
$ aws_okta_keyman
16:48:22   (INFO) AWS Okta Keyman 🔐 v0.7.0
Password:

16:48:31   (INFO) Using factor: 📲 Duo Push
16:48:33   (WARNING) Duo required; check your phone... 📱
16:48:40   (INFO) Waiting for MFA success...
16:48:41   (INFO) Successfully authed Nathan V
16:48:41   (WARNING) No app ID provided; select from available AWS accounts

    Account
[0] AWS - Sandbox
[1] AWS - Development
[2] AWS - Staging
[3] AWS - Integration
[4] AWS - Production
Selection: 4

16:48:47   (INFO) Using account: AWS - Production / exampleAppIDFromOkta/123
16:48:47   (INFO) Getting SAML Assertion from example
16:48:48   (WARNING) Multiple AWS roles found; please select one

    Account          Role
[0] example-prod     Admin
[1] example-prod     Dev
Selection: 0

16:48:51   (INFO) Getting SAML Assertion from example
16:48:51   (INFO) Assuming role: arn:aws:iam::1234567890:role/Admin
16:48:52   (INFO) Wrote profile "default" to /home/nathan/.aws/credentials 💾
16:48:52   (INFO) Current time is 2019-11-08 00:48:52.265393
16:48:52   (INFO) Session expires at 2019-11-08 01:48:52+00:00 ⏳
16:48:52   (INFO) All done! 👍
```

### Troubleshooting
Troubleshooting information is available on the project Github [wiki].

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

## Developer Info
See CONTRIBUTING.md for more information on contributing to this project.

## License
Copyright 2020 Nathan V

Copyright 2018 Nextdoor.com, Inc

Licensed under the Apache License, Version 2.0. See LICENSE.txt file for details.

Some code in `aws_okta_keyman/okta.py`, `aws_okta_keyman/aws.py`,
`aws_okta_keyman/aws_saml.py`, and `aws_okta_keyman/test/aws_saml_test.py` is
distributed under MIT license. See the source files for details. A copy of the
license is in the LICENSE_MIT.txt file.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fnathan-v%2Faws_okta_keyman.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fnathan-v%2Faws_okta_keyman?ref=badge_large)

[nd_okta_auth]: https://github.com/Nextdoor/nd_okta_auth
[nextdoorinc]: https://github.com/Nextdoor
[oktaauth]: https://github.com/ThoughtWorksInc/oktaauth
[aws_role_credentials]: https://github.com/ThoughtWorksInc/aws_role_credentials
[thoughtworksinc]: https://github.com/ThoughtWorksInc
[tracking]: https://aws.amazon.com/blogs/security/how-to-easily-identify-your-federated-users-by-using-aws-cloudtrail/
[pythonbeginner]: https://wiki.python.org/moin/BeginnersGuide/Download
[okta_aws_guide]: https://support.okta.com/help/servlet/fileField?retURL=%2Fhelp%2Farticles%2FKnowledge_Article%2FAmazon-Web-Services-and-Okta-Integration-Guide&entityId=ka0F0000000MeyyIAC&field=File_Attachment__Body__s
[okta_mfa]: https://www.okta.com/products/adaptive-multi-factor-authentication/
[okta_verify]: https://www.okta.com/blog/tag/okta-verify-with-push/
[aws_saml]: http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
[duo_auth]: https://duo.com/
[keyring]: https://github.com/jaraco/keyring
[wiki]: https://github.com/nathan-v/aws_okta_keyman/wiki#faq--troubleshooting
