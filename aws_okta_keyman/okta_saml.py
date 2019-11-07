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
"""This contains all of the Okta SML specific code."""
from __future__ import unicode_literals
import base64
import logging

import bs4
import requests

from aws_okta_keyman import okta


LOG = logging.getLogger(__name__)


class OktaSaml(okta.Okta):
    """Handle the SAML part of talking to Okta."""

    def assertion(self, saml):
        """Parse the assertion from the SAML response."""
        assertion = ''
        soup = bs4.BeautifulSoup(saml, 'html.parser')
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                assertion = inputtag.get('value')
        return base64.b64decode(assertion)

    def get_okta_error_from_response(self, resp):
        """Parse the Okta error from the HTML response."""
        err = ''
        soup = bs4.BeautifulSoup(resp.text, 'html.parser')
        for err_div in soup.find_all("div", {"class": "error-content"}):
            err = err_div.select('h1')[0].text.strip()
        if err == '':
            err = 'Unknown error'
        return err

    def get_assertion(self, appid):
        """Call Okta and get the assertion."""
        path = '{url}/home/amazon_aws/{appid}'.format(
            url=self.base_url, appid=appid)
        resp = self.session.get(path,
                                cookies={'sid': self.session_token})
        LOG.debug(resp.__dict__)

        try:
            resp.raise_for_status()
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError) as err:
            if err.response.status_code == 404:
                LOG.fatal("Provided App ID {} not found".format(appid))
            else:
                LOG.error('Unknown error: {msg}'.format(
                    msg=str(err.response.__dict__)))
            raise okta.UnknownError()

        assertion = self.assertion(resp.text)
        if assertion == b'':
            err = self.get_okta_error_from_response(resp)
            LOG.fatal(err)
            raise okta.UnknownError()
        return assertion
