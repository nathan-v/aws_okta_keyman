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

from aws_okta_keyman import duo
if sys.version_info[0] < 3:  # pragma: no cover
    from exceptions import Exception  # Python 2

LOG = logging.getLogger(__name__)

BASE_URL = 'https://{organization}.okta.com'
PREVIEW_BASE_URL = 'https://{organization}.oktapreview.com'


class UnknownError(Exception):
    """Some Expected Return Was Received."""


class EmptyInput(BaseException):
    """Invalid Input - Empty String Detected."""


class InvalidPassword(BaseException):
    """Invalid Password."""


class ReauthNeeded(BaseException):
    """Raised when the SAML Assertion is invalid and we need to reauth."""
    def __init__(self, state_token=None):
        self.state_token = state_token
        super(ReauthNeeded, self).__init__()


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

    def __init__(self, organization, username, password, duo_factor=None,
                 oktapreview=False):
        if oktapreview:
            self.base_url = PREVIEW_BASE_URL.format(organization=organization)
        else:
            self.base_url = BASE_URL.format(organization=organization)

        LOG.debug('Base URL Set to: {url}'.format(url=self.base_url))

        # Validate the inputs are reasonably sane
        for input_value in (organization, username, password):
            if input_value == '' or input_value is None:
                raise EmptyInput()

        self.username = username
        self.password = password
        self.duo_factor = duo_factor
        self.session = requests.Session()
        self.session_token = None
        self.long_token = True

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
                                 allow_redirects=False,
                                 cookies={'sid': self.session_token})

        resp.raise_for_status()
        resp_obj = resp.json()
        LOG.debug(resp_obj)
        return resp_obj

    def set_token(self, ret):
        """Parse an authentication response, get a long-lived token, store it
        Parses a SUCCESSFUL authentication response from Okta to get the
        one time use token, requests a long-lived sessoin token from Okta,  and
        stores the new token.
        Args:
            ret: The response from Okta that we know is successful and contains
            a sessionToken
        """
        if self.session_token:
            # We have a session token already
            return
        first_name = ret['_embedded']['user']['profile']['firstName']
        last_name = ret['_embedded']['user']['profile']['lastName']
        LOG.info('Successfully authed {first_name} {last_name}'.format(
            first_name=first_name, last_name=last_name))

        LOG.debug('Long-lived token needed; requesting Okta API token')
        resp = self._request('/sessions',
                             {'sessionToken': ret['sessionToken']})
        self.session_token = resp['id']

    def validate_mfa(self, fid, state_token, passcode):
        """Validate an Okta user with Passcode-based MFA.

        Takes in the supplied Factor ID (fid), State Token and user supplied
        Passcode, and validates the auth. If successful, sets the session
        token. If invalid, raises an exception.

        Args:
            fid: Okta Factor ID (returned in the PasscodeRequired exception)
            state_token: State Token (returned in the PasscodeRequired
            exception)
            passcode: The user-supplied Passcode to verify

        Returns:
            True/False whether or not authentication was successful
        """
        if len(passcode) > 6 or len(passcode) < 5:
            LOG.error('Passcodes must be 5 or 6 digits')
            return None

        valid = self.send_user_response(fid, state_token, passcode, 'passCode')
        if valid:
            self.set_token(valid)
            return True
        return None

    def validate_answer(self, fid, state_token, answer):
        """Validate an Okta user with Question-based MFA.

        Takes in the supplied Factor ID (fid), State Token and user supplied
        Passcode, and validates the auth. If successful, sets the session
        token. If invalid, raises an exception.

        Args:
            fid: Okta Factor ID (returned in the PasscodeRequired exception)
            state_token: State Token (returned in the PasscodeRequired
            exception)
            answer: The user-supplied answer to verify

        Returns:
            True/False whether or not authentication was successful
        """
        if not answer:
            LOG.error('Answer cannot be blank')
            return None

        valid = self.send_user_response(fid, state_token, answer, 'answer')
        if valid:
            self.set_token(valid)
            return True
        return None

    def send_user_response(self, fid, state_token, user_response, resp_type):
        """Call Okta with a factor response and verify it.

        Args:
            fid: Okta factor ID
            state_token: Okta state token
            user_response: String response from the user
            resp_type: String, type of response (Okta defined)

        Returns:
            Dict (JSON) of the API call response
        """
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token,
                resp_type: user_response}
        try:
            return self._request(path, data)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 403:
                LOG.error('Invalid Passcode Detected')
                return None
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

        Returns:
            Bool for success or failure of the MFA
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

    def duo_auth(self, fid, state_token, passcode=None):
        """Trigger a Duo Auth request.

        This method is meant to be called by self.auth() if a Login session
        requires MFA, and the users profile supports Duo.

        If web is requested we set up a local web server for web auth and then
        open a browser for the user. This is going to be left in place in case
        in the future Duo breaks the current method for getting around the web
        version.

        If web is not requested we will try to fake out Duo to move ahead with
        MFA without needing to use their iframe format.

        In either case we then immediately go into a wait loop. Each time we
        loop around, we pull the latest status for that push event. If it's
        declined we will throw an error. If its accepted, we write out our
        SessionToken.

        Args:
            fid: Okta Factor ID used to trigger the push
            state_token: State Token allowing us to trigger the push
            passcode: OTP passcode string

        Returns:
            Dict (JSON) of API response for the MFA status if successful
            otherwise None
        """
        if self.duo_factor is None:
            # Prompt user for which Duo factor to use
            raise duo.FactorRequired(id, state_token)

        if self.duo_factor == "passcode" and not passcode:
            raise duo.PasscodeRequired(fid, state_token)

        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token}
        ret = self._request(path, data)
        verification = ret['_embedded']['factor']['_embedded']['verification']

        auth = None
        duo_client = duo.Duo(verification, state_token, self.duo_factor)
        if self.duo_factor == "web":
            # Duo Web via local browser
            LOG.warning('Duo required; opening browser...')
            proc = Process(target=duo_client.trigger_web_duo)
            proc.start()
            time.sleep(2)
            webbrowser.open_new('http://127.0.0.1:65432/duo.html')
        elif self.duo_factor == "passcode":
            # Duo auth with OTP code without a browser
            LOG.warning('Duo required; using OTP...')
            auth = duo_client.trigger_duo(passcode=passcode)
        else:
            # Duo Auth without the browser
            LOG.warning('Duo required; check your phone... 📱')
            auth = duo_client.trigger_duo()

        if auth is not None:
            self.mfa_callback(auth, verification, state_token)
            ret = self.mfa_wait_loop(ret, data)
            if ret:
                self.set_token(ret)
                return True
        return None

    def mfa_wait_loop(self, ret, data, sleep=2):
        """Wait loop that keeps checking Okta for MFA status.

        Args:
            ret: Dict (JSON) response from a previous API call
            data: Dict that must be submitted as part of the MFA API call
            sleep: Int to change the sleep time between loops

        Returns:
            Dict (JSON) of API response for the MFA status if successful
            otherwise None
        """
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
            raise

    def auth(self, state_token=None):
        """Perform an initial authentication against Okta.

        The initial Okta Login authentication is handled here - and optionally
        MFA authentication is triggered. If successful, this method stores a
        SessionToken. This SessionToken can be used to initiate a call to the
        "Embed Link" of an Okta Application.

        **Note ... Undocumented/Unclear Okta Behavior**
        If you use the SessionToken only to make your subsequent requests, it's
        usable only once and then it expires. However, if you combine it with a
        long-lived SID cookie (which we do, by using requests.Session() to make
        all of our web requests), then that SessionToken can be redeemed many
        times as long as you do it through the "Embed Links". See the OktaSaml
        client for an example.

            https://developer.okta.com/use_cases/authentication/
            session_cookie#visit-an-embed-link-with-the-session-token
        """
        path = '/authn'
        data = {'username': self.username,
                'password': self.password}
        if state_token:
            data = {'stateToken': state_token}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 401:
                raise InvalidPassword()
            raise

        status = ret.get('status', None)

        if status == 'SUCCESS':
            self.set_token(ret)
            return None

        if status in ('MFA_ENROLL', 'MFA_ENROLL_ACTIVATE'):
            LOG.warning('User {u} needs to enroll in 2FA first'.format(
                u=self.username))

        if status in ('MFA_REQUIRED', 'MFA_CHALLENGE'):
            return self.handle_mfa_response(ret)

        raise UnknownError(status)

    def handle_mfa_response(self, ret):
        """In the case of an MFA response evaluate the response and handle
        accordingly based on available MFA factors.

        Args:
            ret: Dict (JSON) response from a previous API call

        Returns:
            Bool if a push factor was used and it succeeds
        """
        response_types = ['sms', 'question', 'call', 'token:software:totp']
        push_factors = []
        response_factors = []
        for factor in ret['_embedded']['factors']:
            if factor['factorType'] == 'push':
                LOG.debug('Okta Verify factor found')
                push_factors.append(factor)
            if factor['provider'] == 'DUO':
                LOG.debug('Duo Auth factor found')
                push_factors.append(factor)
            if factor['factorType'] in response_types:
                LOG.debug("{} factor found".format(factor['factorType']))
                response_factors.append(factor)

        if len(response_factors) + len(push_factors) == 0:
            LOG.debug("Factors from Okta: {}".format(
                ret['_embedded']['factors']))
            LOG.fatal('No supported MFA types found')
            raise UnknownError('No supported MFA types found')

        if self.handle_push_factors(push_factors, ret['stateToken']):
            return True

        self.handle_response_factors(response_factors, ret['stateToken'])
        return None

    def handle_push_factors(self, factors, state_token):
        """Handle  any push-type factors.

        Args:
            factors: Dict of supported MFA push factors from Okta
            state_token: String, Okta state token

        Returns:
            Bool for success or failure of the MFA
        """
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
        """Handle any OTP-type factors.

        Raises back to keyman.py to interact with the user for an OTP response

        Args:
            factors: Dict of supported MFA push factors from Okta
            state_token: String, Okta state token
        """
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

    def get_aws_apps(self):
        """Call Okta to get a list of the AWS apps that a user is able to
        access

        Returns: Dict of AWS account IDs and names
        """
        path = "/users/me/appLinks"
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}
        url = '{base}/api/v1{path}'.format(base=self.base_url, path=path)
        cookies = {'sid': self.session_token}

        resp = self.session.get(url=url, headers=headers,
                                allow_redirects=False, cookies=cookies)
        resp_obj = resp.json()

        resp.raise_for_status()

        aws_list = {i['label']: i['linkUrl'] for i in resp_obj
                    if i['appName'] == 'amazon_aws'}

        accounts = []
        for key, val in aws_list.items():
            appid = val.split("/", 5)[5]
            accounts.append({'name': key, 'appid': appid})
        return accounts

    def mfa_callback(self, auth, verification, state_token):
        """Do callback to Okta with the info from the MFA provider

        Args:
            auth: String auth from MFA provider to send in the callback
            verification: Dict of details used in Okta API calls
            state_token: String Okta state token
        """
        app = verification['signature'].split(":")[1]
        response_sig = "{}:{}".format(auth, app)
        callback_params = "stateToken={}&sig_response={}".format(
            state_token, response_sig)

        url = "{}?{}".format(
            verification['_links']['complete']['href'],
            callback_params)
        ret = self.session.post(url)
        if ret.status_code != 200:
            raise Exception("Bad status from Okta callback {}".format(
                ret.status_code))
