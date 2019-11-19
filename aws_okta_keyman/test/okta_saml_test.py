from __future__ import unicode_literals

import sys
import unittest

import requests

from aws_okta_keyman.okta import UnknownError, ReauthNeeded
from aws_okta_keyman.okta_saml import OktaSaml

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock

EXAMPLE_ASSERTION = (
    '<!DOCTYPE html><html lang="en"><body id="app" class="enduser-app">'
    '<form id="appForm" '
    'action="https://signin.aws.amazon.com/saml" method="POST">'
    '<input name="SAMLResponse" type="hidden" value="SAMLSAMLSAML"/>'
    '<input name="RelayState" type="hidden" value=""/></form></body></html>')


AWS_HTML_ERROR = (
    '<!DOCTYPE html><html lang="en"><body>'
    '<div class="error-content"><h1>BAD STUFF</h1></div></body></html>')


class MockResponse:
    def __init__(self, headers, status_code, text):
        self.headers = headers
        self.text = text
        self.status_code = status_code
        self.url = ''

    def text(self):
        return self.text

    def raise_for_status(self):
        pass


class OktaSAMLTest(unittest.TestCase):

    def test_assertion(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        ret = okta_saml.assertion(EXAMPLE_ASSERTION)
        self.assertEqual(ret, b"H\x03\x0bH\x03\x0bH\x03\x0b")

    def test_get_okta_error_from_response(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        response = MockResponse('', 200, 'html')
        ret = okta_saml.get_okta_error_from_response(response)

        self.assertEqual(ret, 'Unknown error')

    def test_get_okta_error_from_response_specific(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        response = MockResponse('', 200, AWS_HTML_ERROR)
        ret = okta_saml.get_okta_error_from_response(response)

        self.assertEqual(ret, 'BAD STUFF')

    def test_get_state_token_from_html_format_a(self):
        html = b"\n  var stateToken = \'win\';\n"
        ret = OktaSaml.get_state_token_from_html(html)

        self.assertEqual(ret, 'win')

    def test_get_state_token_from_html_format_b(self):
        html = b"\n  var stateToken = \'win\x2Dning\';\n"
        ret = OktaSaml.get_state_token_from_html(html)

        self.assertEqual(ret, 'win-ning')

    def test_get_state_token_from_html_format_c(self):
        html = b"\n  var stateToken = \'win\\x2Dning\';\n"
        ret = OktaSaml.get_state_token_from_html(html)

        self.assertEqual(ret, 'win-ning')

    def test_get_assertion_successful(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.assertion.return_value = 'assertion'
        okta_saml.session = mock.MagicMock()
        okta_saml.session.get.return_value = MockResponse(None, None, 'assert')

        ret = okta_saml.get_assertion('foo')

        okta_saml.assertion.assert_has_calls([mock.call('assert')])
        self.assertEqual(ret, 'assertion')

    def test_get_assertion_missing(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.assertion.return_value = b''
        okta_saml.session = mock.MagicMock()
        okta_saml.session.get.return_value = MockResponse(None, None, 'assert')
        okta_saml.get_okta_error_from_response = mock.MagicMock()

        with self.assertRaises(UnknownError):
            okta_saml.get_assertion('foo')

        okta_saml.get_okta_error_from_response.assert_has_calls([mock.ANY])

    def test_get_assertion_404(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.session = mock.MagicMock()
        resp = requests.Response()
        resp.status_code = 404
        resp.url = ''
        okta_saml.session.get.return_value = resp

        with self.assertRaises(UnknownError):
            okta_saml.get_assertion('foo')

    def test_get_assertion_500(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.session = mock.MagicMock()
        resp = requests.Response()
        resp.status_code = 500
        resp.url = ''
        okta_saml.session.get.return_value = resp

        with self.assertRaises(UnknownError):
            okta_saml.get_assertion('foo')

    def test_get_assertion_2FA(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.session = mock.MagicMock()
        resp = MockResponse(None, None, 'assert')
        resp.url = 'https://foo.bar/second-factor?zort=yep'
        okta_saml.session.get.return_value = resp
        okta_saml.get_state_token_from_html = mock.MagicMock()
        okta_saml.get_state_token_from_html.return_value = 'token'

        with self.assertRaises(ReauthNeeded) as err:
            okta_saml.get_assertion('foo')

        exc = err.exception
        self.assertEqual(exc.state_token, 'token')

    def test_get_assertion_2FA_no_token(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.session = mock.MagicMock()
        resp = MockResponse(None, None, 'assert')
        resp.url = 'https://foo.bar/second-factor?zort=yep'
        okta_saml.session.get.return_value = resp
        okta_saml.get_state_token_from_html = mock.MagicMock()
        okta_saml.get_state_token_from_html.side_effect = AttributeError

        with self.assertRaises(ReauthNeeded) as err:
            okta_saml.get_assertion('foo')

        exc = err.exception
        self.assertEqual(exc.state_token, None)
