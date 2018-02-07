from __future__ import unicode_literals
import unittest
import requests
import sys
from nd_okta_auth import okta
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
                'firstName': 'Bob', 'timeZone':
                'America/Los_Angeles'},
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
MFA_CHALLENGE_RESPONSE_PASSCODE = {
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


class OktaTest(unittest.TestCase):

    def test_init_blank_inputs(self):
        with self.assertRaises(okta.EmptyInput):
            okta.Okta(organization='', username='test', password='test')

        with self.assertRaises(okta.EmptyInput):
            okta.Okta(organization=None, username='test', password='test')

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
            json={'test': True},
            url='https://organization.okta.com/api/v1/test',
            allow_redirects=False)

        # Validate that we got back the expected_dict
        self.assertEquals(ret, expected_dict)

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
            json={'test': True},
            url='http://test/test',
            allow_redirects=False)

        # Validate that we got back the expected_dict
        self.assertEquals(ret, expected_dict)

    def test_request_bad_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')

        class TestExc(Exception):
            '''Test Exception'''

        fake_response_object = mock.MagicMock(name='response')
        fake_response_object.raise_for_status.side_effect = TestExc()

        client.session.post.return_value = fake_response_object
        with self.assertRaises(TestExc):
            client._request('/test', {'test': True})

    def test_set_token(self):
        client = okta.Okta('organization', 'username', 'password')
        client.session = mock.MagicMock(name='session')
        client.set_token(SUCCESS_RESPONSE)
        self.assertEquals(client.session_token, 'XXXTOKENXXX')

    def test_validate_mfa_too_short(self):
        client = okta.Okta('organization', 'username', 'password')
        ret = client.validate_mfa('fid', 'token', '123')
        self.assertEquals(False, ret)

    def test_validate_mfa_invalid_token(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        resp = requests.Response()
        resp.status_code = 403
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        ret = client.validate_mfa('fid', 'token', '123456')
        self.assertEquals(False, ret)

        client._request.assert_has_calls([
            mock.call(
                '/authn/factors/fid/verify',
                {'fid': 'fid', 'stateToken': 'token', 'passCode': '123456'})
        ])

    def test_validate_mfa_unknown_error(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        resp = requests.Response()
        resp.status_code = 500
        resp.body = 'Something bad happened'
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(okta.UnknownError):
            client.validate_mfa('fid', 'token', '123456')

    def test_validate_mfa(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client._request.return_value = SUCCESS_RESPONSE
        ret = client.validate_mfa('fid', 'token', '123456')
        self.assertEquals(ret, True)
        self.assertEquals(client.session_token, 'XXXTOKENXXX')

    def test_okta_verify_with_push(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        ret = client.okta_verify_with_push('123', 'token', sleep=0)
        self.assertEquals(ret, True)

    def test_okta_verify_with_push_rejected(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_REJECTED_RESPONSE,
        ]

        ret = client.okta_verify_with_push('123', 'token', sleep=0)
        self.assertEquals(ret, False)

    def test_okta_verify_with_push_timeout(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_TIMEOUT_RESPONSE,
        ]

        ret = client.okta_verify_with_push('123', 'token', sleep=0)
        self.assertEquals(ret, False)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('webbrowser.open_new')
    @mock.patch('nd_okta_auth.okta.Process')
    def test_duo_auth(self, process_mock, _web_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        process_mock.start.return_value = None

        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            SUCCESS_RESPONSE,
        ]

        ret = client.duo_auth('user', '123', 'token', sleep=0)
        self.assertEquals(ret, True)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('webbrowser.open_new')
    @mock.patch('nd_okta_auth.okta.Process')
    def test_duo_auth_rejected(self, process_mock, _web_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        process_mock.start.return_value = None

        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_REJECTED_RESPONSE,
        ]

        ret = client.duo_auth('user', '123', 'token', sleep=0)
        self.assertEquals(ret, False)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('webbrowser.open_new')
    @mock.patch('nd_okta_auth.okta.Process')
    def test_duo_auth_timeout(self, process_mock, _web_mock, _sleep_mock):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        process_mock.start.return_value = None

        client._request.side_effect = [
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_WAITING_RESPONSE,
            MFA_TIMEOUT_RESPONSE,
        ]

        ret = client.duo_auth('user', '123', 'token', sleep=0)
        self.assertEquals(ret, False)

    def test_auth_bad_password(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        resp = requests.Response()
        resp.status_code = 401
        resp.body = 'Bad Password'
        client._request.side_effect = requests.exceptions.HTTPError(
            response=resp)

        with self.assertRaises(okta.InvalidPassword):
            client.auth()

    def test_auth(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [SUCCESS_RESPONSE]

        ret = client.auth()
        self.assertEquals(ret, None)

    def test_auth_requires_mfa_enroll(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [MFA_ENROLL_RESPONSE]

        with self.assertRaises(okta.UnknownError):
            client.auth()

    def test_auth_trigger_okta_verify(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client.okta_verify_with_push = mock.MagicMock(
            name='okta_verify_with_push')

        client._request.side_effect = [MFA_CHALLENGE_RESPONSE_OKTA_VERIFY]

        ret = client.auth()
        self.assertEquals(ret, None)
        client.okta_verify_with_push.assert_has_calls([
            mock.call('abcd', 'token')
        ])

    def test_auth_trigger_okta_verify_canceled(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client.okta_verify_with_push = mock.MagicMock(
            name='okta_verify_with_push')
        client.okta_verify_with_push.side_effect = KeyboardInterrupt

        client._request.side_effect = [MFA_CHALLENGE_RESPONSE_OKTA_VERIFY]

        with self.assertRaises(okta.UnknownError):
            client.auth()

    def test_auth_trigger_duo_auth(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')
        client.duo_auth = mock.MagicMock(
            name='duo_auth')

        client._request.side_effect = [MFA_CHALLENGE_RESPONSE_DUO_AUTH]

        ret = client.auth()
        self.assertEquals(ret, None)
        client.duo_auth.assert_has_calls([
            mock.call(123, 'abcd', 'token')
        ])

    def test_auth_throws_passcode_required(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [MFA_CHALLENGE_RESPONSE_PASSCODE]

        with self.assertRaises(okta.PasscodeRequired):
            client.auth()

    def test_auth_with_unexpected_response(self):
        client = okta.Okta('organization', 'username', 'password')
        client._request = mock.MagicMock(name='_request')

        client._request.side_effect = [{}]

        with self.assertRaises(okta.UnknownError):
            client.auth()
