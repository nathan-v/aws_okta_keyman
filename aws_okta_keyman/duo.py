# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright 2018 Nathan V

from multiprocessing import Process
import sys
import time
if sys.version_info[0] < 3:  # pragma: no cover
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
else:
    from http.server import HTTPServer, BaseHTTPRequestHandler


class QuietHandler(BaseHTTPRequestHandler, object):
    '''
    We have to do this HTTP sever siliness because the Duo widget has to be
    presented over HTTP or HTTPS or the callback won't work.
    '''
    def __init__(self, html, *args):
        self.html = html
        super(QuietHandler, self).__init__(*args)

    def log_message(self, _format, *args):
        # This quiets the server log to prevent request logging in the terminal
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.html.encode('utf-8'))
        return


class Duo:
    def __init__(self, details, state_token):
        self.details = details
        self.token = state_token
        self.html = None

    def trigger_duo(self):
        host = self.details['host']
        sig = self.details['signature']
        script = self.details['_links']['script']['href']
        callback = self.details['_links']['complete']['href']

        self.html = '''<p style="text-align:center">You may close this
         after the next page loads successfully</p>
        <iframe id="duo_iframe" style="margin: 0 auto;display:block;"
        width="620" height="330" frameborder="0"></iframe>
        <form method="POST" id="duo_form" action="{cb}">
        <input type="hidden" name="stateToken" value="{tkn}" /></form>
        <script src="{scr}"></script><script>Duo.init(
          {{'host': '{hst}','sig_request': '{sig}','post_action': '{cb}'}}
        );</script>'''.format(tkn=self.token, scr=script,
                              hst=host, sig=sig,
                              cb=callback)

        p = Process(target=self.duo_webserver)
        p.start()
        time.sleep(10)
        p.terminate()

    def duo_webserver(self):
        server_address = ('127.0.0.1', 65432)
        httpd = HTTPServer(server_address, self.handler_with_html)
        httpd.serve_forever()

    def handler_with_html(self, *args):
        QuietHandler(self.html, *args)
