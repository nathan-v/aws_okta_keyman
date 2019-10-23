from __future__ import unicode_literals

import sys
import unittest

import requests

from aws_okta_keyman.okta import UnknownError
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


class MockResponse:
    def __init__(self, headers, status_code, text):
        self.headers = headers
        self.text = text
        self.status_code = status_code

    def text(self):
        return self.text

    def raise_for_status(self):
        pass


class OktaSAMLTest(unittest.TestCase):

    def test_assertion(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        ret = okta_saml.assertion(EXAMPLE_ASSERTION)
        self.assertEqual(ret, b"H\x03\x0bH\x03\x0bH\x03\x0b")

    def test_get_assertion_successful(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.assertion.return_value = 'assertion'
        okta_saml.session = mock.MagicMock()
        okta_saml.session.get.return_value = MockResponse(None, None, 'assert')
        ret = okta_saml.get_assertion('foo', 'bar')

        okta_saml.assertion.assert_has_calls([mock.call('assert')])
        self.assertEqual(ret, 'assertion')

    def test_get_assertion_404(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.session = mock.MagicMock()
        resp = requests.Response()
        resp.status_code = 404
        okta_saml.session.get.return_value = resp

        with self.assertRaises(UnknownError):
            okta_saml.get_assertion('foo', 'bar')

    def test_get_assertion_500(self):
        okta_saml = OktaSaml('org', 'user', 'password')
        okta_saml.assertion = mock.MagicMock()
        okta_saml.session = mock.MagicMock()
        resp = requests.Response()
        resp.status_code = 500
        okta_saml.session.get.return_value = resp

        with self.assertRaises(UnknownError):
            okta_saml.get_assertion('foo', 'bar')
