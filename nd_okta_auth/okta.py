'''
okta
^^^^

Handles the initial Okta authentication - throws appropriate errors in the
events of bad passwords, MFA requirements, etc.
'''

import base64
import exceptions
import logging
import time

import bs4
import requests

log = logging.getLogger(__name__)


class BaseException(exceptions.Exception):
    '''Base Exception for Okta Auth'''


class UnknownError(exceptions.Exception):
    '''Some Expected Return Was Received'''


class EmptyInput(BaseException):
    '''Invalid Input - Empty String Detected'''


class InvalidPassword(BaseException):
    '''Invalid Password'''


class PasscodeRequired(BaseException):
    '''A 2FA Passcode Must Be Entered'''

    def __init__(self, fid, state_token):
        self.fid = fid
        self.state_token = state_token


class OktaVerifyRequired(BaseException):
    '''OktaVerify Authentication Is Required'''


class Okta(object):

    url = '/app/{app}/{appid}/sso/saml'

    def __init__(self, server, username, password):
        self.base_url = 'https://{server}'.format(server=server)
        log.debug('Base URL Set to: {url}'.format(url=self.base_url))

        # Validate the inputs are reasonably sane
        for input in (server, username, password):
            if (input == '' or input is None):
                raise EmptyInput()

        self.username = username
        self.password = password

    def _request(self, path, data=None):
        '''Basic URL Fetcher for Okta

        Any HTTPError is raised immediately, otherwise the response is parsed
        as JSON and passed back as a dictionary.

        Args:
            path: The path at the base url to call
            data: Optional data to pass in as Post parameters

        Returns:
            The response in dict form.
        '''
        headers = {'Accept': 'application/json',
                   'Content-Type': 'application/json'}

        if path.startswith('http'):
            url = path
        else:
            url = '{base}/api/v1{path}'.format(base=self.base_url, path=path)

        resp = requests.post(url=url, headers=headers, json=data)

        resp_obj = resp.json()
        log.debug(resp_obj)

        resp.raise_for_status()
        return resp_obj

    def set_token(self, ret):
        '''Parses an authentication response and stores the token.

        Parses a SUCCESSFUL authentication response from Okta and stores the
        token.

        args:
            ret: The response from Okta that we know is successful and contains
            a sessionToken
        '''
        firstName = ret['_embedded']['user']['profile']['firstName']
        lastName = ret['_embedded']['user']['profile']['lastName']
        log.info('Successfully authed {firstName} {lastName}'.format(
            firstName=firstName, lastName=lastName))
        self.session_token = ret['sessionToken']

    def validate_mfa(self, fid, state_token, passcode):
        '''Validates an Okta user with Passcode-based MFA.

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
        '''
        if len(passcode) != 6:
            log.error('Passcodes must be 6 digits')
            return False

        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token,
                'passCode': passcode}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                log.error('Invalid Passcode Detected')
                return False
            raise UnknownError(e.response.body)

        self.set_token(ret)
        return True

    def _okta_verify(self, fid, state_token):
        log.warning('Okta Verify Push being sent...')
        path = '/authn/factors/{fid}/verify'.format(fid=fid)
        data = {'fid': fid,
                'stateToken': state_token}
        ret = self._request(path, data)

        while ret['status'] != 'SUCCESS':
            log.info('Waiting for Okta Verification...')
            time.sleep(1)

            if ret.get('factorResult', 'REJECTED') == 'REJECTED':
                log.error('Okta Verify Push REJECTED')
                return False

            links = ret.get('_links', {})
            ret = self._request(links['next']['href'], data)

        self.set_token(ret)
        return True

    def auth(self):
        '''Performs an initial authentication against Okta.

        This either returns a successful and useful SessionToken, or it raises
        an appropriate exception (for example, if MFA is required).
        '''
        path = '/authn'
        data = {'username': self.username,
                'password': self.password}
        try:
            ret = self._request(path, data)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise InvalidPassword()

        status = ret.get('status', None)

        if status == 'SUCCESS':
            self.set_token(ret)

        if status == 'MFA_ENROLL' or status == 'MFA_ENROLL_ACTIVATE':
            log.warning('User {u} needs to enroll in 2FA first'.format(
                u=self.username))
            raise UnknownError()

        if status == 'MFA_REQUIRED' or status == 'MFA_CHALLENGE':
            for factor in ret['_embedded']['factors']:
                if factor['factorType'] == 'push':
                    if self._okta_verify(factor['id'], ret['stateToken']):
                        return

            for factor in ret['_embedded']['factors']:
                if factor['factorType'] == 'token:software:totp':
                    raise PasscodeRequired(
                        fid=factor['id'],
                        state_token=ret['stateToken'])

        raise UnknownError(status)


class OktaSaml(Okta):

    def assertion(self, saml):
        assertion = ''
        soup = bs4.BeautifulSoup(saml, 'html.parser')
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                assertion = inputtag.get('value')

        return base64.b64decode(assertion)

    def get_assertion(self, appid, apptype):
        path = '{url}/app/{apptype}/{appid}/sso/saml'.format(
            url=self.base_url, apptype=apptype, appid=appid)
        resp = requests.get(path, params={'onetimetoken': self.session_token})

        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            log.error('Unknown error: {msg}'.format(str(e.response.__dict__)))
            raise UnknownError()

        return self.assertion(resp.text.decode('utf8'))
