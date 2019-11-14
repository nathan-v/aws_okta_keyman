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
import re

import bs4
import requests

from aws_okta_keyman import okta


LOG = logging.getLogger(__name__)


class OktaSaml(okta.Okta):
    """Handle the SAML part of talking to Okta."""

    @staticmethod
    def assertion(html):
        """Parse the assertion from the SAML response.

        Args:
        html: Bytes string from AWS response

        Returns: String of the assertion
        """
        assertion = ''
        soup = bs4.BeautifulSoup(html, 'html.parser')
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                assertion = inputtag.get('value')
        return base64.b64decode(assertion)

    @staticmethod
    def get_okta_error_from_response(resp):
        """Parse the Okta error from the HTML response.

        Args:
        resp: Requests response object

        Returns: String error from the HTML
        """
        err = ''
        soup = bs4.BeautifulSoup(resp.text, 'html.parser')
        for err_div in soup.find_all("div", {"class": "error-content"}):
            err = err_div.select('h1')[0].text.strip()
        if err == '':
            err = 'Unknown error'
        return err

    @staticmethod
    def get_state_token_from_html(html):
        """Parse the Okta HTML response for a state token we need. Luckily the
        format is inconsistent..

        Args:
        html: Bytes string html contents from requests

        Returns: String state token
        """
        # Find the token
        match = re.search("var stateToken = \\'(.{,50})\\'", str(html))

        # Clean it up (result like '00n-DFVdfv-dgfhjgndfdfBVFV')
        token = match.group(1).replace('\\\\x2D', '-')
        token = token.replace('\\x2D', '-')
        return token

    def get_assertion(self, appid):
        """Call Okta and get the assertion.

        Args: String appid

        Returns: String SAML response
        """
        path = '{url}/home/amazon_aws/{appid}'.format(
            url=self.base_url, appid=appid)
        resp = self.session.get(path,
                                cookies={'sid': self.session_token})

        if 'second-factor' in resp.url:
            try:
                state_token = self.get_state_token_from_html(resp.text)
                LOG.debug("Redirected; reuathing with new token")
                raise okta.ReauthNeeded(state_token)
            except AttributeError:
                LOG.debug("Error finding state token in response")
                raise okta.ReauthNeeded()

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
