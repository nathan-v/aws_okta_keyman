[![CircleCI](https://circleci.com/gh/Nextdoor/nd_okta_auth.svg?style=svg&circle-token=7266b58fbbe52af8d01e72ce02d9fae6a7f4d1c6)](https://circleci.com/gh/Nextdoor/nd_okta_auth)

# Nextdoor Okta Auth-er

This is a simple command-line tools for logging into Okta and generating
temporary Amazon AWS Credentials. This tool makes it easy and secure for your
developers to generate short-lived, [logged and user-attributed][tracking]
credentials that can be used for any of the Amazon SDK libraries or CLI tools.

# Features

We have support for logging into Okta, optionally handling MFA Authentication,
and then generating new SAML authenticated AWS sessions. In paritcular, this
tool has a few core features.

## Optional MFA Authentication

If you organization requires MFA for the _[initial login into Okta][okta_mfa]_, 
we will automatically detect that requirement on a per-user basis and prompt
the user to complete the Multi Factor Authentication.

In paritcular, there is support for standard passcode based auth, as well as
support for [Okta Verify with Push][okta_verify]. If both are available,
Okta Verify with Push will be prioritized and a push notification is
_automatically sent to the user_. If the user declines the validation, then
optionally the Passcode can be entered in manually.

## Re-Up Mode .. Automatic Credential Re-Generation

Amazon IAM only supports Federated Login sessions that last up to *1 hour*. For
developers, it can be painful to re-authenticate every hour during your work
day. This is made much worse if your organization requires MFA on each login.

You may run the Okta Auth-er tool in "reup" mode to get around this. The tool
will stay running in a daemon-like mode, and it will reach out regularly to
Okta, generate a new SAML Assertion, and then generate updated Amazon AWS
credentials. This can run for as long as your Okta administrator has allowed
your Login Session to be - often a full work day.

See the `--reup` commandline option for help here!

# Usage

For detailed usage instructions, see the `--help` commandline argument. Basic
instructions though:

    $ nd_okta_auth -a <application id> -o <your org name> -u <your username>
    08:27:44   (INFO) Nextdoor Okta Auther v0.0.1
    Password: 
    08:27:48   (WARNING) Okta Verify Push being sent...
    08:27:48   (INFO) Waiting for Okta Verification...
    ...
    08:28:09   (INFO) Waiting for Okta Verification...
    08:28:10   (INFO) Successfully authed Matt Wise
    08:28:10   (INFO) Getting SAML Assertion from foobar
    08:28:11   (INFO) Found credentials in shared credentials file: ~/.aws/credentials
    08:28:11   (INFO) Wrote profile "default" to /Users/diranged/.aws/credentials
    08:28:11   (INFO) Session expires at 2017-07-24 16:28:13+00:00
    $

## Okta Setup
Before you can use this tool, your Okta administrator needs to set up
[Amazon/Okta integration][okta_aws_guide] using SAML roles.

## Inspiration
This code is heavily based on the previous work done by
[ThoughtWorksInc][thoughtworksinc] on their [OktaAuth][oktaauth] and [AWS Role
Credentials][aws_role_credentials] tools. We took their general purpose code
and re-wrote them into a singularly focused tool that added some new features.

In particular, we found it clumsy to use two CLI tools together to do a single
task. Additionally, the tools did not have support for [Okta Verify with
Push][okta_verify].

# Developer Setup

If you are interested in working on the codebase, setting up your development
environment is quick and easy.

    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install -r requirements.txt

## Running Tests

    $ nosetests -vv --with-coverage --cover-erase --cover-package=nd_okta_auth

[oktaauth]: https://github.com/ThoughtWorksInc/oktaauth
[aws_role_credentials]: https://github.com/ThoughtWorksInc/aws_role_credentials
[thoughtworksinc]: https://github.com/ThoughtWorksInc
[tracking]: https://aws.amazon.com/blogs/security/how-to-easily-identify-your-federated-users-by-using-aws-cloudtrail/
[okta_aws_guide]: https://support.okta.com/help/servlet/fileField?retURL=%2Fhelp%2Farticles%2FKnowledge_Article%2FAmazon-Web-Services-and-Okta-Integration-Guide&entityId=ka0F0000000MeyyIAC&field=File_Attachment__Body__s
[okta_mfa]: https://www.okta.com/products/adaptive-multi-factor-authentication/
[okta_verify]: https://www.okta.com/blog/tag/okta-verify-with-push/
[aws_saml]: http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
