from __future__ import unicode_literals

import sys
import unittest

import requests

from aws_okta_keyman import okta, duo

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


# Successful response message from Okta when you have fully logged in
SUCCESS_RESPONSE = {
    'status': 'SUCCESS',
    'expiresAt': '2017-07-24T17:05:59.000Z',
    '_embedded': {
        'user': {
            'profile': {
                'locale': 'en',
                'lastName': 'Foo',
                'login': 'bob@foobar.com',
                'firstName': 'Bob',
                'timeZone': 'America/Los_Angeles'},
            'id': 'XXXIDXXX'
        }
    },
    'sessionToken': 'XXXTOKENXXX'}

# Miniaturized versions of the Okta response objects... they are too large to
# really store here, and its not necessary.
MFA_ENROLL_RESPONSE = {
    'status': 'MFA_ENROLL',
    'stateToken': 'token',
}
MFA_CHALLENGE_RESPONSE_OKTA_VERIFY = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'push',
                'provider': 'OKTA',
                'id': 'abcd',
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_RESPONSE_DUO_AUTH = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'user': {
            'id': 123
        },
        'factors': [
            {
                'factorType': 'web',
                'provider': 'DUO',
                'id': 'abcd',
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_OKTA_OTP = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'token:software:totp',
                'provider': 'OKTA',
                'id': 'abcd',
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_GOOGLE_OTP = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'token:software:totp',
                'provider': 'GOOGLE',
                'id': 'abcd',
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_SMS_OTP = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'sms',
                'provider': 'OKTA',
                'id': 'abcd',
                'profile': {'phoneNumber': '(xxx) xxx-1234'},
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_CALL_OTP = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'call',
                'provider': 'OKTA',
                'id': 'abcd',
                'profile': {'phoneNumber': '(xxx) xxx-1234'},
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_QUESTION = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'question',
                'provider': 'OKTA',
                'id': 'abcd',
                'profile':
                    {'question': 'what_is_your_quest?',
                     'questionText': 'What is your quest?'},
            }
        ]
    },
    'stateToken': 'token',
}
MFA_CHALLENGE_RSA_TOKEN = {
    'status': 'MFA_REQUIRED',
    '_embedded': {
        'factors': [
            {
                'factorType': 'token',
                'provider': 'RSA',
                'id': 'abcd',
            }
        ]
    },
    'stateToken': 'token',
}
MFA_WAITING_RESPONSE = {
    'status': 'MFA_CHALLENGE',
    'factorResult': 'WAITING',
    '_links': {
        'next': {
            'href': 'https://foobar.okta.com/api/v1/authn/factors/X/verify',
        }
    },
    'stateToken': 'token',
    '_embedded': {
        'factor': {
            '_embedded': {
                'verification': {}
            }
        }
    },
}
MFA_REJECTED_RESPONSE = {
    'status': 'MFA_CHALLENGE',
    'factorResult': 'REJECTED',
    '_links': {
        'next': {
            'href': 'https://foobar.okta.com/api/v1/authn/factors/X/verify',
        }
    },
    'stateToken': 'token',
    '_embedded': {
        'factor': {
            '_embedded': {
                'verification': {}
            }
        }
    },
}
MFA_TIMEOUT_RESPONSE = {
    'status': 'MFA_CHALLENGE',
    'factorResult': 'TIMEOUT',
    '_links': {
        'next': {
            'href': 'https://foobar.okta.com/api/v1/authn/factors/X/verify',
        }
    },
    'stateToken': 'token',
    '_embedded': {
        'factor': {
            '_embedded': {
                'verification': {}
            }
        }
    },
}


class MockResponse:
    def __init__(self, headers, status_code):
        self.headers = headers
        self.status_code = status_code


class OktaTest(unittest.TestCase):

    def test_init_blank_inputs(self):
        with self.assertRaises(okta.EmptyInput):
            okta.Okta(organization='', username='test', password='test')

        with self.assertRaises(okta.EmptyInput):
            okta.Okta(organization=None, username='test', password='test')

    def test_init_args_values(self):
        client = okta.Okta(organization='foo', username='bar', password='baz',
                           oktapreview=True)

        self.assertEqual(client.base_url, 'https://foo.oktapreview.com')
        self.assertEqual(client.username, 'bar')
        self.assertEqual(client.password, 'baz')

    def test_request_good_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        # Ultimately this is the dict we want to get back
        expected_dict = {'ok': True}

        # Create a fake requests.post() response object mock that returns the
        # expected_dict above when json() is called
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = expected_dict

        client.session.post.return_value = fake_response_object
        ret = client._request('/test', {'test': True})

        # Validate that the call went out as expected, with the supplied input
        client.session.post.assert_called_with(
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            cookies={'sid': None},
            json={'test': True},
            url='https://organization.okta.com/api/v1/test',
            allow_redirects=False)

        # Validate that we got back the expected_dict
        self.assertEqual(ret, expected_dict)

    def test_request_with_full_url(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        # Ultimately this is the dict we want to get back
        expected_dict = {'ok': True}

        # Create a fake requests.post() response object mock that returns the
        # expected_dict above when json() is called
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = expected_dict

        client.session.post.return_value = fake_response_object
        ret = client._request('http://test/test', {'test': True})

        # Validate that the call went out as expected, with the supplied input
        client.session.post.assert_called_with(
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            cookies={'sid': None},
            json={'test': True},
            url='http://test/test',
            allow_redirects=False)

        # Validate that we got back the expected_dict
        self.assertEqual(ret, expected_dict)

    def test_request_bad_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        class TestExc(Exception):
            """Test Exception"""

        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.raise_for_status.side_effect = TestExc()

        client.session.post.return_value = fake_response_object
        with self.assertRaises(TestExc):
            client._request('/test', {'test': True})

    def test_set_token(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')
        client._request = mock.MagicMock()
        client._request.return_value = {'id': 'LongToken'}
        client.set_token(SUCCESS_RESPONSE)
        self.assertEqual(client.session_token, 'LongToken')
        client._request.assert_has_calls([
            mock.call('/sessions', {'sessionToken': 'XXXTOKENXXX'})
            ])

    def test_set_token_skip_if_exists(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session_token = 'woot'
        client.session = mock.MagicMock(name='session')
        client._request = mock.MagicMock()
        client._request.return_value = {'id': 'LongToken'}

        client.set_token(SUCCESS_RESPONSE)

        self.assertEqual(client.session_token, 'woot')
        assert not client._request.called

    def test_validate_mfa(self):
        client = okta.Okta('organization', 'username', 'password')
        client.send_user_response = mock.MagicMock(name='send_user_response')
        client.send_user_response.return_value = {True}
        client.set_token = mock.MagicMock()
        ret = client.validate_mfa('fid', 'token', '123456')
        self.assertEqual(ret, True)
        client.set_token.assert_called_with({True})

    def test_validate_mfa_too_short(self):
        client = okta.Okta('organization', 'username', 'password')
        ret = client.validate_mfa('fid', 'token', '123')
        self.assertEqual(None, ret)

    def test_validate_mfa_failed(self):
        client = okta.Okta('organization', 'username', 'password')
        client.send_user_response = mock.MagicMock(name='send_user_response')
        client.send_user_response.return_value = False
        client.set_token = mock.MagicMock()
        ret = client.validate_mfa('fid', 'token', '123456')
        self.assertEqual(None, ret)

    def test_validate_answer(self):
        client = okta.Okta('organization', 'username', 'password')
        client.send_user_response = mock.MagicMock(name='send_user_response')
        client.send_user_response.return_value = {True}
        client.set_token = mock.MagicMock()
        ret = client.validate_answer('fid', 'token', '123456')
        self.assertEqual(ret, True)
        client.set_token.assert_called_with({True})

    def test_validate_answer_too_short(self):
        client = okta.Okta('organization', 'username', 'password')
        ret = client.validate_answer('fid', 'token', '')
        self.assertEqual(None, ret)

    def test_validate_answer_failed(self):
        client = okta.Okta('organization', 'username', 'password')
        client.send_user_response = mock.MagicMock(name='send_user_response')
        client.send_user_response.return_value = False
        client.set_token = mock.MagicMock()
        ret = client.validate_answer('fid', 'token', '123456')
        self.assertEqual(None, ret)

    def test_send_user_response(self):
        client = okta.Okta('organization', 'username', 'password')
        resp = requests.Response()
        resp.status_code = 200
        resp.body = 'Dat'
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = resp

        ret = client.send_user_response('fid', 'token', '123456', 'passCode')
        self.assertEqual(200, ret.status_code)

        client._request.assert_has_calls([
            mock.call(
                '/authn/factors/fid/verify',
                {'fid': 'fid', 'stateToken': 'token', 'passCode': '123456'})
        ])

    def test_send_user_response_invalid_token(self):
        client = okta.Okta('organization', 'username', 'password')
        resp = requests.Response()
        resp.status_code = 403
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        ret = client.send_user_response('fid', 'token', '123456', 'passCode')
        self.assertEqual(None, ret)

    def test_send_user_response_retries_exceeded(self):
        client = okta.Okta('organization', 'username', 'password')
        resp = requests.Response()
        resp.status_code = 401
        resp.body = 'Too many failures'
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(okta.UnknownError):
            client.send_user_response('fid', 'token', '123456', 'passCode')

    def test_send_user_response_unknown_error(self):
        client = okta.Okta('organization', 'username', 'password')
        resp = requests.Response()
        resp.status_code = 500
        resp.body = 'Something bad happened'
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(okta.UnknownError):
            client.send_user_response('fid', 'token', '123456', 'passCode')

    def test_okta_verify(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.set_token = mock.MagicMock()
        client._request.return_value = MFA_WAITING_RESPONSE

        ret = client.okta_verify('123', 'token')
        self.assertEqual(ret, True)
        client.mfa_wait_loop.assert_called_with(MFA_WAITING_RESPONSE,
                                                {'fid': '123',
                                                 'stateToken': 'token'})

    def test_okta_verify_failure(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.mfa_wait_loop.return_value = None

        ret = client.okta_verify('123', 'token')
        self.assertEqual(ret, None)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.okta.duo.Duo')
    def test_duo_auth_missing_factor(self, _duo_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.duo_factor = None

        with self.assertRaises(duo.FactorRequired):
            client.duo_auth('123', 'token')

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.okta.duo.Duo')
    def test_duo_auth_missing_passcode(self, _duo_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.duo_factor = "passcode"

        with self.assertRaises(duo.PasscodeRequired):
            client.duo_auth('123', 'token')

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.okta.duo.Duo')
    def test_duo_auth_successful_push(self, duo_mock, _sleep_mock):
        duo_instance = duo_mock.return_value
        duo_instance.trigger_duo.return_value = True
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.mfa_callback = mock.MagicMock()
        client.set_token = mock.MagicMock()
        client.duo_factor = "push"

        ret = client.duo_auth('123', 'token')
        self.assertEqual(ret, True)
        client.mfa_wait_loop.assert_called_with(MFA_WAITING_RESPONSE,
                                                {'fid': '123',
                                                 'stateToken': 'token'})
        client.mfa_callback.assert_called_with(True, {}, 'token')

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.duo.Duo')
    def test_duo_auth_successful_passcode(self, duo_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        duo_instance = duo_mock.return_value
        duo_instance.trigger_duo.return_value = True
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.mfa_callback = mock.MagicMock()
        client.set_token = mock.MagicMock()
        client.duo_factor = "passcode"

        client.duo_auth('123', 'token', '000000')
        duo_instance.trigger_duo.assert_called_with(passcode='000000')
        client.mfa_callback.assert_called_with(True, {}, 'token')

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('webbrowser.open_new')
    @mock.patch('aws_okta_keyman.okta.Process')
    @mock.patch('aws_okta_keyman.okta.duo.Duo')
    def test_duo_auth_web(self, duo_mock, process_mock, web_mock,
                          _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        process_mock.start.return_value = None
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.mfa_wait_loop.return_value = None
        client.duo_factor = "web"

        ret = client.duo_auth('123', 'token')
        self.assertEqual(ret, None)
        web_mock.assert_has_calls([
            mock.call(u'http://127.0.0.1:65432/duo.html')])
        assert not duo_mock.trigger_duo.called

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.okta.duo.Duo')
    def test_duo_auth_failure(self, _duo_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = MFA_WAITING_RESPONSE
        client.mfa_wait_loop = mock.MagicMock(name='mfa_wait_loop')
        client.mfa_wait_loop.return_value = None
        client.mfa_callback = mock.MagicMock()
        client.duo_factor = "push"

        ret = client.duo_auth('123', 'token')
        self.assertEqual(ret, None)

    def test_auth(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [SUCCESS_RESPONSE]
        client.set_token = mock.MagicMock()

        ret = client.auth()

        self.assertEqual(ret, None)
        client._request.assert_has_calls([
            mock.call('/authn',
                      {'username': 'username', 'password': 'password'})
        ])

    def test_auth_with_token(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [SUCCESS_RESPONSE]
        client.set_token = mock.MagicMock()

        client.auth('token')

        client._request.assert_has_calls([
            mock.call('/authn',
                      {'stateToken': 'token'})
        ])

    def test_auth_mfa_challenge(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [MFA_CHALLENGE_RESPONSE_OKTA_VERIFY]
        client.handle_mfa_response = mock.MagicMock(name='handle_mfa_response')
        client.handle_mfa_response.return_value = None

        ret = client.auth()
        self.assertEqual(ret, None)

    def test_auth_bad_password(self):
        client = okta.Okta('organization', 'username', 'password')
        resp = requests.Response()
        resp.status_code = 401
        resp.body = 'Bad Password'
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(okta.InvalidPassword):
            client.auth()

    def test_auth_call_error(self):
        client = okta.Okta('organization', 'username', 'password')
        resp = requests.Response()
        resp.status_code = 403
        resp.body = 'Bad Password'
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(requests.exceptions.HTTPError):
            client.auth()

    def test_auth_with_unexpected_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [{}]

        with self.assertRaises(okta.UnknownError):
            client.auth()

    def test_auth_requires_mfa_enroll(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [MFA_ENROLL_RESPONSE]

        with self.assertRaises(okta.UnknownError):
            client.auth()

    def test_handle_mfa_response_trigger_okta_verify(self):
        client = okta.Okta('organization', 'username', 'password')
        client.handle_push_factors = mock.MagicMock(
            name='handle_push_factors')
        client.handle_push_factors.return_value = True

        client.handle_mfa_response(MFA_CHALLENGE_RESPONSE_OKTA_VERIFY)

        client.handle_push_factors.assert_has_calls([
            mock.call(
                [{'factorType': 'push', 'provider': 'OKTA', 'id': 'abcd'}],
                'token')
        ])

    def test_handle_mfa_response_trigger_duo_auth(self):
        client = okta.Okta('organization', 'username', 'password')
        client.handle_push_factors = mock.MagicMock(
            name='handle_push_factors')
        client.handle_push_factors.return_value = True

        client.handle_mfa_response(MFA_CHALLENGE_RESPONSE_DUO_AUTH)
        client.handle_push_factors.assert_has_calls([
            mock.call([{'factorType': 'web', 'provider': 'DUO', 'id': 'abcd'}],
                      'token')
        ])

    def test_handle_mfa_response_trigger_sms_otp(self):
        client = okta.Okta('organization', 'username', 'password')
        client.handle_push_factors = mock.MagicMock()
        client.handle_push_factors.return_value = False
        client.handle_response_factors = mock.MagicMock(
            name='handle_response_factors')
        passcode = okta.PasscodeRequired('', '', '')
        client.handle_response_factors.side_effect = passcode

        with self.assertRaises(okta.PasscodeRequired):
            client.handle_mfa_response(MFA_CHALLENGE_SMS_OTP)
        client.handle_response_factors.assert_has_calls([
            mock.call([{'factorType': 'sms', 'provider': 'OKTA', 'id': 'abcd',
                        'profile': {'phoneNumber': '(xxx) xxx-1234'}}],
                      'token')
        ])

    def test_handle_mfa_response_returns_none(self):
        client = okta.Okta('organization', 'username', 'password')
        client.handle_push_factors = mock.MagicMock()
        client.handle_push_factors.return_value = False
        client.handle_response_factors = mock.MagicMock()

        ret = client.handle_mfa_response(MFA_CHALLENGE_SMS_OTP)

        self.assertEqual(ret, None)

    def test_handle_mfa_response_unsupported(self):
        client = okta.Okta('organization', 'username', 'password')
        client.handle_push_factors = mock.MagicMock()
        client.handle_push_factors.return_value = False

        with self.assertRaises(okta.UnknownError):
            client.handle_mfa_response(MFA_CHALLENGE_RSA_TOKEN)

    def test_handle_push_factors_empty(self):
        client = okta.Okta('organization', 'username', 'password')

        ret = client.handle_push_factors([], 'token')

        self.assertEqual(ret, False)

    def test_handle_push_factors_okta_verify(self):
        client = okta.Okta('organization', 'username', 'password')
        client.okta_verify = mock.MagicMock(name='okta_verify')
        client.okta_verify.return_value = True
        factor = MFA_CHALLENGE_RESPONSE_OKTA_VERIFY['_embedded']['factors']

        ret = client.handle_push_factors(factor, 'token')

        self.assertEqual(ret, True)
        client.okta_verify.assert_has_calls([
            mock.call('abcd', 'token')
        ])

    def test_handle_push_factors_duo_auth(self):
        client = okta.Okta('organization', 'username', 'password')
        client.duo_auth = mock.MagicMock(name='duo_auth')
        client.duo_auth.return_value = True
        duo_factor = MFA_CHALLENGE_RESPONSE_DUO_AUTH['_embedded']['factors']

        ret = client.handle_push_factors(duo_factor, 'token')

        self.assertEqual(ret, True)
        client.duo_auth.assert_has_calls([
            mock.call('abcd', 'token')
        ])

    def test_mfa_wait_loop_success(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            SUCCESS_RESPONSE,
        ]
        data = {'fid': '123', 'stateToken': 'token'}

        ret = client.mfa_wait_loop(MFA_WAITING_RESPONSE, data, sleep=0)
        expected = {
            '_embedded': {
                'user': {
                    'id': 'XXXIDXXX',
                    'profile': {
                        'firstName': 'Bob',
                        'lastName': 'Foo',
                        'locale': 'en',
                        'login': 'bob@foobar.com',
                        'timeZone': 'America/Los_Angeles'
                    }
                }
            },
            'expiresAt': mock.ANY,
            'sessionToken': 'XXXTOKENXXX',
            'status': 'SUCCESS'}
        self.assertEqual(ret, expected)

    def test_mfa_wait_loop_rejected(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_REJECTED_RESPONSE,
        ]
        data = {'fid': '123', 'stateToken': 'token'}

        ret = client.mfa_wait_loop(MFA_WAITING_RESPONSE, data, sleep=0)
        self.assertEqual(ret, None)

    def test_mfa_wait_loop_timeout(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            KeyboardInterrupt
        ]
        data = {'fid': '123', 'stateToken': 'token'}

        with self.assertRaises(KeyboardInterrupt):
            client.mfa_wait_loop(MFA_WAITING_RESPONSE, data, sleep=0)

    def test_mfa_wait_loop_user_cancel(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_TIMEOUT_RESPONSE,
        ]
        data = {'fid': '123', 'stateToken': 'token'}

        ret = client.mfa_wait_loop(MFA_WAITING_RESPONSE, data, sleep=0)
        self.assertEqual(ret, None)

    def test_handle_response_factors_none(self):
        client = okta.Okta('organization', 'username', 'password')
        ret = client.handle_response_factors([], 'foo')
        self.assertEqual(ret, None)

    def test_handle_response_factors_sms(self):
        client = okta.Okta('organization', 'username', 'password')
        client.request_otp = mock.MagicMock()
        with self.assertRaises(okta.PasscodeRequired):
            client.handle_response_factors(
                MFA_CHALLENGE_SMS_OTP['_embedded']['factors'],
                'foo')
        client.request_otp.assert_has_calls([mock.call('abcd', 'foo', 'SMS')])

    def test_handle_response_factors_call(self):
        client = okta.Okta('organization', 'username', 'password')
        client.request_otp = mock.MagicMock()
        with self.assertRaises(okta.PasscodeRequired):
            client.handle_response_factors(
                MFA_CHALLENGE_CALL_OTP['_embedded']['factors'],
                'foo')
        client.request_otp.assert_has_calls([
            mock.call('abcd', 'foo', 'phone call')
        ])

    def test_handle_response_factors_question(self):
        client = okta.Okta('organization', 'username', 'password')
        client.request_otp = mock.MagicMock()
        with self.assertRaises(okta.AnswerRequired):
            client.handle_response_factors(
                MFA_CHALLENGE_QUESTION['_embedded']['factors'],
                'foo')

    def test_handle_response_factors_google(self):
        client = okta.Okta('organization', 'username', 'password')
        client.request_otp = mock.MagicMock()
        with self.assertRaises(okta.PasscodeRequired):
            client.handle_response_factors(
                MFA_CHALLENGE_GOOGLE_OTP['_embedded']['factors'],
                'foo')

    def test_handle_response_factors_okta(self):
        client = okta.Okta('organization', 'username', 'password')
        client.request_otp = mock.MagicMock()
        with self.assertRaises(okta.PasscodeRequired):
            client.handle_response_factors(
                MFA_CHALLENGE_OKTA_OTP['_embedded']['factors'],
                'foo')

    def test_request_otp(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_TIMEOUT_RESPONSE,
        ]

        client.request_otp('foo', 'bar', 'sms')
        client._request.assert_has_calls([
            mock.call('/authn/factors/foo/verify',
                      {'fid': 'foo', 'stateToken': 'bar'})
        ])

    def test_get_aws_apps(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock()
        json_response = [
            {'label': 'label1', 'linkUrl': '/////1', 'appName': 'amazon_aws'},
            {'label': 'label2', 'linkUrl': '/////2', 'appName': 'amazon_aws'},
            {'label': 'label1', 'linkUrl': 'URL1', 'appName': 'not_aws'},
        ]
        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.json.return_value = json_response
        client.session.get.return_value = fake_response_object

        ret = client.get_aws_apps()
        assert {'name': 'label1', 'appid': '1'} in ret
        assert {'name': 'label2', 'appid': '2'} in ret

    def test_mfa_callback_success(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock()
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        client.session.post.return_value = MockResponse(
            headers, 200)
        verification = {'signature': 'somesig:differentsig', '_links': {
                        'complete': {'href': 'http://example.com/callback'}}}
        client.mfa_callback('auth', verification, 'token')

        client.session.assert_has_calls([
            mock.call.post(
                ('http://example.com/callback?stateToken=token&'
                 'sig_response=auth:differentsig'))])

    def test_mfa_callback_failure(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock()
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        client.session.post.return_value = MockResponse(
            headers, 500)
        verification = {'signature': 'somesig:differentsig', '_links': {
                        'complete': {'href': 'http://example.com/callback'}}}

        with self.assertRaises(Exception):
            client.mfa_callback('auth', verification, 'token')


class PasscodeRequiredTest(unittest.TestCase):
    def test_class_properties(self):
        error_response = None
        try:
            raise okta.PasscodeRequired('fid', 'state_token', 'provider')
        except okta.PasscodeRequired as err:
            error_response = err

        self.assertEqual(error_response.fid, 'fid')
        self.assertEqual(error_response.state_token, 'state_token')
        self.assertEqual(error_response.provider, 'provider')


class AnswerRequiredTest(unittest.TestCase):
    def test_class_properties(self):
        error_response = None
        try:
            raise okta.AnswerRequired('factor', 'state_token')
        except okta.AnswerRequired as err:
            error_response = err

        self.assertEqual(error_response.factor, 'factor')
        self.assertEqual(error_response.state_token, 'state_token')


class ReauthNeededTest(unittest.TestCase):
    def test_class_properties(self):
        error_response = None
        try:
            raise okta.ReauthNeeded('state_token')
        except okta.ReauthNeeded as err:
            error_response = err

        self.assertEqual(error_response.state_token, 'state_token')
