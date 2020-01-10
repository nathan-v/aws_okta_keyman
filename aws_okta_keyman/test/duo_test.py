from __future__ import unicode_literals

import sys
import unittest

from aws_okta_keyman import duo

if sys.version_info[0] < 3:
    import mock  # Python 2
    from StringIO import StringIO as IO
else:
    from unittest import mock  # Python 3
    from io import BytesIO as IO

DETAILS = {
    'host': 'somehost',
    'signature': 'somesig:differentsig',
    '_links': {
        'script': {
            'href': 'http://example.com/script.js'
        },
        'complete': {
            'href': 'http://example.com/callback'
        },
    },
}

HTML = ('''<p style="text-align:center">You may close this after the\n'''
        '''         next page loads successfully</p>\n        '''
        '''<iframe id="duo_iframe" style="margin: 0 auto;display:block;"\n'''
        '''        width="620" height="330" frameborder="0"></iframe>\n'''
        '''        <form method="POST" id="duo_form" '''
        '''action="http://example.com/callback">\n        '''
        '''<input type="hidden" name="stateToken" value="token" /></form>\n'''
        '''        <script src="http://example.com/script.js"></script>'''
        '''<script>Duo.init(\n          '''
        '''{\'host\': \'somehost\',\'sig_request\': \'somesig\','''
        '''\'post_action\': \'http://example.com/callback\'}\n'''
        '''        );</script>''')


class MockResponse:
    def __init__(self, headers, status_code, json_data):
        self.headers = headers
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


class TestDuo(unittest.TestCase):

    def setup_for_trigger_duo(self, factor):
        self.duo_test = duo.Duo(DETAILS, 'token', factor)
        self.duo_test.do_auth = mock.MagicMock()
        self.duo_test.do_auth.return_value = "sid"
        self.duo_test.get_txid = mock.MagicMock()
        self.duo_test.get_txid.return_value = 'txid'
        self.duo_test.get_status = mock.MagicMock()
        self.duo_test.get_status.return_value = 'auth'

    def test_init_missing_args(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            duo.Duo()

    def test_init_with_args(self):
        duo_test = duo.Duo(DETAILS, 'token')
        self.assertEqual(duo_test.details, DETAILS)
        self.assertEqual(duo_test.token, 'token')

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.duo.Process')
    def test_trigger_web_duo(self, process_mock, _sleep_mock):
        process_mock.start.return_value = None

        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.trigger_web_duo()

        process_mock.assert_has_calls([
            mock.call().start(),
            mock.call().terminate(),

        ])

    @mock.patch('aws_okta_keyman.duo.HTTPServer')
    def test_duo_webserver(self, server_mock):
        server_mock.return_value = mock.MagicMock()

        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.duo_webserver()

        server_mock.assert_has_calls([
            mock.call(('127.0.0.1', 65432), duo_test.handler_with_html),
            mock.call().serve_forever()
        ])

    @mock.patch('aws_okta_keyman.duo.QuietHandler')
    def test_handler(self, qh_mock):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.handler_with_html('foo', 'bar', 'baz')

        assert qh_mock.called

        qh_mock.assert_has_calls([
            mock.call(None, 'foo', 'bar', 'baz')
        ])

    def test_trigger_duo_nofactor(self):
        self.setup_for_trigger_duo(None)
        with self.assertRaises(Exception):
            self.duo_test.trigger_duo()
        self.duo_test.do_auth.assert_has_calls([mock.call(None, None)])

    def test_trigger_duo_passcode_missing(self):
        self.setup_for_trigger_duo('passcode')
        with self.assertRaises(Exception):
            self.duo_test.trigger_duo()

    def test_trigger_duo_passcode_success(self):
        self.setup_for_trigger_duo('passcode')
        self.duo_test.trigger_duo('123456')
        self.duo_test.get_txid.assert_has_calls(
            [mock.call('sid', 'Passcode', '123456')])
        self.duo_test.get_status.assert_has_calls([mock.call('txid', 'sid')])

    def test_trigger_duo_call_success(self):
        self.setup_for_trigger_duo('call')
        self.duo_test.trigger_duo()
        self.duo_test.get_txid.assert_has_calls(
            [mock.call('sid', 'Phone+Call')])
        self.duo_test.get_status.assert_has_calls([mock.call('txid', 'sid')])

    def test_trigger_duo_push_success(self):
        self.setup_for_trigger_duo('push')
        self.duo_test.trigger_duo()
        self.duo_test.get_txid.assert_has_calls(
            [mock.call('sid', 'Duo+Push')])
        self.duo_test.get_status.assert_has_calls([mock.call('txid', 'sid')])

    def test_do_auth_302_success(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.session.params = mock.MagicMock()
        duo_test.session.post.return_value = mock.MagicMock()
        duo_test.session.post.return_value.status_code = 302
        duo_test.session.post.return_value.headers = {
            'Location': 'https://someurl/foo?sid=somesid'}
        ret = duo_test.do_auth('sid', 'certs_url')

        self.assertEqual(duo_test.session.params,
                         {'certs_url': 'certs_url', 'sid': 'sid'})
        self.assertEqual(duo_test.session.headers,
                         {'Origin': 'https://somehost',
                          'Content-Type': 'application/x-www-form-urlencoded'})
        duo_test.session.assert_has_calls(
            [mock.call.post(
                ('https://somehost/frame/web/v1/auth?tx=somesig&parent='
                 'http://0.0.0.0:3000/duo&v=2.1'), allow_redirects=False)])
        self.assertEqual(ret, 'somesid')

    def test_do_auth_302_location_missing(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.session.params = mock.MagicMock()
        duo_test.session.post.return_value = mock.MagicMock()
        duo_test.session.post.return_value.status_code = 302
        duo_test.session.post.return_value.headers = {}

        with self.assertRaises(Exception):
            duo_test.do_auth('sid', 'certs_url')

    def test_do_auth_200(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.session.params = mock.MagicMock()
        json = {'response': {'sid': 'sid', 'certs_url': 'certs_url'}}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.side_effect = [
            MockResponse(headers, 200, json), MockResponse(headers, 302, json)]
        ret = duo_test.do_auth(None, 'certs_url')

        self.assertEqual(ret, 'somesid')

    def test_do_auth_500(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.session.params = mock.MagicMock()
        duo_test.session.post.return_value = mock.MagicMock()
        duo_test.session.post.return_value.status_code = 500

        with self.assertRaises(Exception):
            duo_test.do_auth('sid', 'certs_url')

    def test_get_txid_with_passcode(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        json = {'response': {'txid': 'txid'}}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(headers, 200, json)
        ret = duo_test.get_txid('sid', 'factor', '000000')

        duo_test.session.assert_has_calls([
            mock.call.post(('https://somehost/frame/prompt?sid=sid&device='
                            'phone1&factor=factor&out_of_date=False&'
                            'passcode=000000'))])
        self.assertEqual(ret, 'txid')

    def test_get_txid_without_passcode(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        json = {'response': {'txid': 'txid'}}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(headers, 200, json)
        ret = duo_test.get_txid('sid', 'factor')

        duo_test.session.assert_has_calls([
            mock.call.post(('https://somehost/frame/prompt?sid=sid&device='
                            'phone1&factor=factor&out_of_date=False'))])
        self.assertEqual(ret, 'txid')

    @mock.patch('time.sleep', return_value=None)
    def test_get_status_success(self, _sleep_mock):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        json_wait = {'stat': 'WAIT'}
        json_ok = {'response': {'cookie': 'yum'}, 'stat': 'OK'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.side_effect = [
            MockResponse(headers, 200, json_wait),
            MockResponse(headers, 200, json_ok)]
        ret = duo_test.get_status('txid', 'sid')

        duo_test.session.assert_has_calls([
            mock.call.post('https://somehost/frame/status?sid=sid&txid=txid'),
            mock.call.post('https://somehost/frame/status?sid=sid&txid=txid')])
        self.assertEqual(ret, 'yum')

    @mock.patch('time.sleep', return_value=None)
    def test_get_status_redirect(self, _sleep_mock):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.do_redirect = mock.MagicMock()
        json_wait = {'stat': 'WAIT'}
        json_ok = {'response': {'result_url': 'url'}, 'stat': 'OK'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.side_effect = [
            MockResponse(headers, 200, json_wait),
            MockResponse(headers, 200, json_ok)]
        duo_test.get_status('txid', 'sid')

        duo_test.do_redirect.assert_has_calls([mock.call('url', 'sid')])

    @mock.patch('time.sleep', return_value=None)
    def test_get_status_500(self, _sleep_mock):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.do_redirect = mock.MagicMock()
        json_wait = {'stat': 'WAIT'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(
            headers, 500, json_wait)

        with self.assertRaises(Exception):
            duo_test.get_status('txid', 'sid')

    @mock.patch('time.sleep', return_value=None)
    def test_get_status_timeout(self, _sleep_mock):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        duo_test.do_redirect = mock.MagicMock()
        json_wait = {'stat': 'WAIT'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(
            headers, 200, json_wait)

        with self.assertRaises(Exception):
            duo_test.get_status('txid', 'sid')

    def test_do_redirect_success(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        json_ok = {'response': {'cookie': 'yum'}, 'stat': 'OK'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(
            headers, 200, json_ok)
        ret = duo_test.do_redirect('url', 'sid')

        duo_test.session.assert_has_calls([
            mock.call.post('https://somehosturl?sid=sid')])
        self.assertEqual(ret, 'yum')

    def test_do_redirect_failure(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        json_ok = {'response': {'cookie': 'yum'}, 'stat': 'OK'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(
            headers, 500, json_ok)

        with self.assertRaises(Exception):
            duo_test.do_redirect('url', 'sid')

    def test_do_redirect_missing_cookie(self):
        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.session = mock.MagicMock()
        json_ok = {'response': {'crumbs': 'yum'}, 'stat': 'OK'}
        headers = {'Location': 'https://someurl/foo?sid=somesid'}
        duo_test.session.post.return_value = MockResponse(
            headers, 200, json_ok)
        ret = duo_test.do_redirect('url', 'sid')

        self.assertEqual(ret, None)


class TestQuietHandler(unittest.TestCase):
    # noinspection PyArgumentList
    def test_init_missing_args(self):
        with self.assertRaises(TypeError):
            duo.QuietHandler()

    def test_init_with_args(self):
        qh_test = duo.QuietHandler(HTML, MockRequestPOST(), 'bar', 'baz')
        self.assertEqual(qh_test.html, HTML)

    def test_log_message(self):
        qh_test = duo.QuietHandler(HTML, MockRequestPOST(), 'bar', 'baz')
        self.assertEqual(qh_test.log_message(''), None)

    def test_do_get(self):
        mr = MockRequest()
        duo.QuietHandler(HTML, mr, 'bar', 'baz')


class PasscodeRequiredTest(unittest.TestCase):
    def test_class_properties(self):
        error_response = None
        try:
            raise duo.PasscodeRequired('factor', 'state_token')
        except duo.PasscodeRequired as err:
            error_response = err

        self.assertEqual(error_response.factor, 'factor')
        self.assertEqual(error_response.state_token, 'state_token')


class FactorRequiredTest(unittest.TestCase):
    def test_class_properties(self):
        error_response = None
        try:
            raise duo.FactorRequired('factor', 'state_token')
        except duo.FactorRequired as err:
            error_response = err

        self.assertEqual(error_response.factor, 'factor')
        self.assertEqual(error_response.state_token, 'state_token')


class MockRequestPOST(object):
    def makefile(self, *args, **kwargs):
        return IO(b"POST /")

    def sendall(self, *args):
        return None


class MockRequest(object):
    def __init__(self):
        self.resp = None

    def makefile(self, *args, **kwargs):
        return IO(b"GET /")

    def sendall(self, *args):
        self.resp = args[0]
        return None
