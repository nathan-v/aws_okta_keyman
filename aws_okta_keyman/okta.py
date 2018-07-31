# -*- coding: utf-8 -*-
#
# Credits: Portions of this code were copied/modified from
# https://github.com/ThoughtWorksInc/oktaauth
#
# Copyright (c) 2015, Peter Gillard-Moss
# All rights reserved.

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""This contains the Okta client code."""
from __future__ import unicode_literals
import logging
import time
from multiprocessing import Process
import sys
import webbrowser

import requests

from aws_okta_keyman.duo import Duo
if sys.version_info[0] < 3:  # pragma: no cover
    from exceptions import Exception  # Python 2

LOG = logging.getLogger(__name__)

BASE_URL = 'https://{organization}.okta.com'
PREVIEW_BASE_URL = 'https://{organization}.oktapreview.com'


class BaseException(Exception):
    """Base Exception for Okta Auth."""


class UnknownError(Exception):
    """Some Expected Return Was Received."""


class EmptyInput(BaseException):
    """Invalid Input - Empty String Detected."""


class InvalidPassword(BaseException):
    """Invalid Password."""


class PasscodeRequired(BaseException):
    """A 2FA Passcode Must Be Entered."""

    def __init__(self, fid, state_token, provider):
        self.fid = fid
        self.state_token = state_token
        self.provider = provider
        super(PasscodeRequired, self).__init__()


class AnswerRequired(BaseException):
    """A 2FA Passcode Must Be Entered."""

    def __init__(self, factor, state_token):
        self.factor = factor
        self.state_token = state_token
        super(AnswerRequired, self).__init__()


class OktaVerifyRequired(BaseException):
    """OktaVerify Authentication Is Required."""


class Okta(object):
    """Base Okta Login Object with MFA handling.

    This base login object handles connecting to Okta, authenticating a user,
    and optionally triggering MFA Authentication. No application specific logic
    is here, just the initial authentication and creation of a
    cookie-authenticated requests.Session() object.

    See OktaSaml for a more useful object.
    """

    def __init__(self, organization, username, password, oktapreview=False, provider=None):
        if oktapreview:
            self.base_url = PREVIEW_BASE_URL.format(organization=organization)
        else:
            self.base_url = BASE_URL.format(organization=organization)

        LOG.debug('Base URL Set to: {url}'.format(url=self.base_url))

        # Validate the inputs are reasonably sane
        for input in (organization, username, password):
            if input == '' or input is None:
                raise EmptyInput()

        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session_token = None
        self.provider = provider.upper()

    def _request(self, path, data=None):
        """Make Okta API calls.

        Any HTTPError is raised immediately, otherwise the response is parsed
        as JSON and passed back as a dictionary.

        Args:
            path: The path at the base url to call
            data: Optional data to pass in as Post parameters

        Returns:
            The response in dict form.
        """
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}

        if path.startswith('http'):
            url = path
        else:
            url = '{base}/api/v1{path}'.format(base=self.base_url, path=path)

        resp = self.session.post(url=url, headers=headers, json=data,
                                 allow_redirects=False)

        resp_obj = resp.json()
        LOG.debug(resp_obj)

        resp.raise_for_status()
        return resp_obj

    def set_token(self, ret):
        """Parse an authentication response and stores the token.

        Parses a SUCCESSFUL authentication response from Okta and stores the
        token.

        args:
            ret: The response from Okta that we know is successful and contains
            a sessionToken
        """
        first_name = ret['_embedded']['user']['profile']['firstName']
        last_name = ret['_embedded']['user']['profile']['lastName']
        LOG.info('Successfully authed {first_name} {last_name}'.format(
            first_name=first_name, last_name=last_name))
        self.session_token = ret['sessionToken']

    def validate_mfa(self, fid, state_token, passcode):
        """Validate an Okta user with Passcode-based MFA.

        Takes in the supplied Factor ID (fid), State Token and user supplied
        Passcode, and validates the auth. If successful, sets the session
        token. If invalid, raises an exception.

        Args:
            fid: Okta Factor ID (returned in the PasscodeRequired exception)
            state_token: State Tken (returned in the PasscodeRequired
            exception)
            passcode: The user-supplied Passcode to verify

        Returns:
            True/False whether or not authentication was successful
        """
        if len(passcode) > 6 or len(passcode) < 5:
            LOG.error('Passcodes must be 5 or 6 digits')
            return False

        valid = self.send_user_response(fid, state_token, passcode, 'passCode')
        if valid:
            self.set_token(valid)
            return True
        else:
            return False

    def validate_answer(self, fid, state_token, answer):
        """Validate an Okta user with Question-based MFA.

        Takes in the supplied Factor ID (fid), State Token and user supplied
        Passcode, and validates the auth. If successful, sets the session
        token. If invalid, raises an exception.

        Args:
            fid: Okta Factor ID (returned in the PasscodeRequired exception)
            state_token: State Tken (returned in the PasscodeRequired
            exception)
            answer: The user-supplied answer to verify

        Returns:
            True/False whether or not authentication was successful
        """
        if len(answer) == 0:
            LOG.error('Answer cannot be blank')
            return False

        valid = self.send_user_response(fid, state_token, answer, 'answer')
        if valid:
            self.set_token(valid)
            return True
        else:
            return False

    def send_user_response(self, fid, state_token, user_response, resp_type):
        """Call Okta with a factor response and verify it."""
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token,
                resp_type: user_response}
        try:
            return self._request(path, data)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 403:
                LOG.error('Invalid Passcode Detected')
                return False
            if err.response.status_code == 401:
                LOG.error('Invalid Passcode Retries Exceeded')
                raise UnknownError('Retries exceeded')

            raise UnknownError(err.response.body)

    def okta_verify(self, fid, state_token):
        """Trigger an Okta Push Verification and waits.

        This method is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports Okta Push with Verify.

        We trigger the push, and then immediately go into a wait loop. Each
        time we loop around, we pull the latest status for that push event. If
        its Declined, we will throw an error. If its accepted, we write out our
        SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
        """
        LOG.warning('Okta Verify Push being sent...')
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token}
        ret = self._request(path, data)

        ret = self.mfa_wait_loop(ret, data)
        if ret:
            self.set_token(ret)
            return True
        return None

    def duo_auth(self, fid, state_token):
        """Trigger a Duo Auth request.

        This method is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports Duo Web.

        We set up a local web server for web auth and then open a browser for
        the user. We then immediately go into a wait loop. Each time we loop
        around, we pull the latest status for that push event. If it's Declined
        we will throw an error. If its accepted, we write out our SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
        """
        LOG.warning('Duo required; opening browser...')
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token}
        ret = self._request(path, data)

        verification = ret['_embedded']['factor']['_embedded']['verification']
        duo = Duo(verification, state_token)
        proc = Process(target=duo.trigger_duo)
        proc.start()
        time.sleep(2)
        webbrowser.open_new('http://127.0.0.1:65432/duo.html')

        ret = self.mfa_wait_loop(ret, data)
        if ret:
            self.set_token(ret)
            return True
        return None

    def mfa_wait_loop(self, ret, data, sleep=1):
        """Wait loop that keeps checking Okta for MFA status."""
        try:
            while ret['status'] != 'SUCCESS':
                LOG.info('Waiting for MFA success...')
                time.sleep(sleep)

                if ret.get('factorResult', 'REJECTED') == 'REJECTED':
                    LOG.error('Duo Push REJECTED')
                    return None

                if ret.get('factorResult', 'TIMEOUT') == 'TIMEOUT':
                    LOG.error('Duo Push TIMEOUT')
                    return None

                links = ret.get('_links')
                ret = self._request(links['next']['href'], data)
            return ret
        except KeyboardInterrupt:
            LOG.info('User canceled waiting for MFA success.')
            return None

    def auth(self):
        """Perform an initial authentication against Okta.

        The initial Okta Login authentication is handled here - and optionally
        MFA authentication is triggered. If successful, this method stores a
        SessionToken. This SessionToken can be used to initiate a call to the
        "Embed Link" of an Okta Application.

        **Note ... Undocumented/Unclear Okta Behavior**
        If you use the SessionToken only to make your subsequent requests, it's
        usable only once and then it expires. However, if you combine it with a
        long-lived SID cookie (which we do, by using reqests.Session() to make
        all of our web requests), then that SessionToken can be redeemd many
        times as long as you do it through the "Embed Links". See the OktaSaml
        client for an example.

            https://developer.okta.com/use_cases/authentication/
            session_cookie#visit-an-embed-link-with-the-session-token
        """
        path = '/authn'
        data = {'username': self.username,
                'password': self.password}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 401:
                raise InvalidPassword()

        status = ret.get('status', None)

        if status == 'SUCCESS':
            self.set_token(ret)
            return None

        if status == 'MFA_ENROLL' or status == 'MFA_ENROLL_ACTIVATE':
            LOG.warning('User {u} needs to enroll in 2FA first'.format(
                u=self.username))

        if status == 'MFA_REQUIRED' or status == 'MFA_CHALLENGE':
            return self.handle_mfa_response(ret)

        raise UnknownError(status)

    def filter_factors(self, factors):
        """Filter the list of factors by the preferred provider.
        """
        filtered = filter(lambda f: f['provider'] == self.provider, factors)
        return list(filtered) if self.provider else factors

    def handle_mfa_response(self, ret):
        """In the case of an MFA response evaluate the response and handle
        accordingly based on available MFA factors.
        """
        factors = filter_factors(ret['_embedded']['factors'])

        response_types = ['sms', 'question', 'call', 'token:software:totp']
        push_factors = []
        response_factors = []

        for factor in factors:
            if factor['factorType'] == 'push':
                LOG.debug('Okta Verify factor found')
                push_factors.append(factor)
            if factor['provider'] == 'DUO':
                LOG.debug('Duo Auth factor found')
                push_factors.append(factor)
            if factor['factorType'] in response_types:
                LOG.debug("{} factor found".format(factor['factorType']))
                response_factors.append(factor)

        if self.handle_push_factors(push_factors, ret['stateToken']):
            return True

        self.handle_response_factors(response_factors, ret['stateToken'])

        # If we haven't returned or raised yet the factor requested isn't
        # supported
        LOG.debug("Factors from Okta: {}".format(
            ret['_embedded']['factors']))
        LOG.fatal('MFA type in use is unsupported')
        raise UnknownError('MFA type in use is unsupported')

    def handle_push_factors(self, factors, state_token):
        """Handle any push-type factors."""
        for factor in factors:
            if factor['factorType'] == 'push':
                LOG.debug('Okta Verify factor found')
                if self.okta_verify(factor['id'], state_token):
                    return True
            if factor['provider'] == 'DUO':
                LOG.debug('Duo Auth factor found')
                if self.duo_auth(factor['id'], state_token):
                    return True
        return False

    def handle_response_factors(self, factors, state_token):
        """Handle any OTP-type factors."""
        otp_provider = None
        otp_factor = None

        for factor in factors:
            if factor['factorType'] == 'sms':
                self.request_otp(factor['id'], state_token, 'SMS')
                phone = factor['profile']['phoneNumber']
                otp_provider = "SMS ({})".format(phone)
                otp_factor = factor['id']
                break
            if factor['factorType'] == 'call':
                self.request_otp(factor['id'], state_token, 'phone call')
                phone = factor['profile']['phoneNumber']
                otp_provider = "call ({})".format(phone)
                otp_factor = factor['id']
                break
            if factor['factorType'] == 'question':
                raise AnswerRequired(factor, state_token)
            if factor['factorType'] == 'token:software:totp':
                otp_provider = factor['provider']
                otp_factor = factor['id']

        if otp_provider:
            raise PasscodeRequired(
                fid=otp_factor,
                state_token=state_token,
                provider=otp_provider)

    def request_otp(self, fid, state_token, otp_type):
        """Trigger an OTP call, SMS, or other and return

        We trigger the push, and then immediately return as the next step is
        essentially just an OTP code entry

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
            otp_type: String shown in log for OTP type
        """
        LOG.warning("Okta {} being requested...".format(otp_type))
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token}
        self._request(path, data)
