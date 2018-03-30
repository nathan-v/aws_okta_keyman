# -*- coding: utf-8 -*-
#
# Credits: This code was copied from
# https://github.com/ThoughtWorksInc/aws_role_credentials
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
"""AWS SAML assertion parser."""
import base64
import xml.etree.ElementTree as ET


class SamlAssertion:
    """Handle the AWS SAML assertion."""

    def __init__(self, assertion):
        self.assertion = assertion

    @staticmethod
    def split_roles(roles):
        """Split out the roles from the string response."""
        return [(y.strip())
                for y
                in roles.text.split(',')]

    @staticmethod
    def sort_roles(roles):
        """Sort and return the AWS roles."""
        return sorted(roles,
                      key=lambda role: 'saml-provider' in role)

    def roles(self):
        """Extract role information from the assertion."""
        attributes = ET.fromstring(self.assertion).iter(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')

        name = 'https://aws.amazon.com/SAML/Attributes/Role'
        roles_attributes = [x for x
                            in attributes
                            if x.get('Name') == name]

        roles_values = [(x.iter(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'))
                        for x
                        in roles_attributes]

        return [(dict(zip(['role', 'principle'],
                          self.sort_roles(self.split_roles(x)))))
                for x
                in roles_values[0]]

    def encode(self):
        """b64 encoding handler."""
        return base64.b64encode(self.assertion).decode()
