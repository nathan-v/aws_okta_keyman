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
    'signature': 'somesig',
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


class TestDuo(unittest.TestCase):
    def test_init_missing_args(self):
        with self.assertRaises(TypeError):
            duo.Duo()

    def test_init_with_args(self):
        duo_test = duo.Duo(DETAILS, 'token')
        self.assertEquals(duo_test.details, DETAILS)
        self.assertEquals(duo_test.token, 'token')

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('aws_okta_keyman.duo.Process')
    def test_trigger_duo(self, process_mock, _sleep_mock):
        process_mock.start.return_value = None

        duo_test = duo.Duo(DETAILS, 'token')
        duo_test.trigger_duo()

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


class TestQuietHandler(unittest.TestCase):
    def test_init_missing_args(self):
        with self.assertRaises(TypeError):
            duo.QuietHandler()

    def test_init_with_args(self):
        qh_test = duo.QuietHandler(HTML, MockRequestPOST(), 'bar', 'baz')
        self.assertEquals(qh_test.html, HTML)

    def test_log_message(self):
        qh_test = duo.QuietHandler(HTML, MockRequestPOST(), 'bar', 'baz')
        self.assertEquals(qh_test.log_message(''), None)

    def test_do_get(self):
        mr = MockRequest()
        duo.QuietHandler(HTML, mr, 'bar', 'baz')


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
