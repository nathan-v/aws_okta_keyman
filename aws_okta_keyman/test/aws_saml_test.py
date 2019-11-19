#!/usr/bin/env python
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

import sys

from aws_okta_keyman.aws_saml import SamlAssertion

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest


idp_arn = 'arn:aws:iam::1111:saml-provider/IDP'
dev_arn = 'arn:aws:iam::1111:role/DevRole'
qa_arn = 'arn:aws:iam::2222:role/QARole'
idp2_arn = 'arn:aws:iam::2222:saml-provider/IDP'


def saml_assertion(roles):
    attribute_value = ('<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001'
                       '/XMLSchema" xmlns:xsi="http://www.w3.org/2001/'
                       'XMLSchema-instance" xsi:type="xs:string">{0}'
                       '</saml2:AttributeValue>')

    roles_values = [(attribute_value.format(x)) for x in roles]

    return ('<?xml version="1.0" encoding="UTF-8"?><saml2p:Response '
            'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0"'
            ' xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Assertion '
            'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="id17773561036281221470153530" '
            'IssueInstant="2015-11-06T10:48:25.399Z" Version="2.0" '
            'xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:'
            'AttributeStatement xmlns:saml2="urn:oasis:names:tc:SAML:2.0:'
            'assertion"><saml2:Attribute Name="https://aws.amazon.com/SAML/'
            'Attributes/Role" NameFormat="urn:oasis:names:tc:'
            'SAML:2.0:attrname-format:uri">{0}</saml2:Attribute></'
            'saml2:AttributeStatement></saml2:Assertion>'
            '</saml2p:Response>').format("".join(roles_values))


class TestSamlAssertion(unittest.TestCase):

    def test_roles_are_extracted(self):
        assertion = saml_assertion(['{},{}'.format(dev_arn, idp_arn)])

        assert SamlAssertion(assertion).roles() == [{'role': dev_arn,
                                                     'principle': idp_arn}]

    def test_principle_can_be_first(self):
        assertion = saml_assertion(['{},{}'.format(idp_arn, dev_arn)])

        assert SamlAssertion(assertion).roles() == [{'role': dev_arn,
                                                     'principle': idp_arn}]

    def test_white_space_is_removed(self):
        assertion = saml_assertion([' {},{} '.format(idp_arn, dev_arn)])

        assert SamlAssertion(assertion).roles() == [{'role': dev_arn,
                                                     'principle': idp_arn}]

    def test_multiple_roles_are_returned(self):
        assertion = saml_assertion(['{},{}'.format(dev_arn, idp_arn),
                                    '{},{}'.format(qa_arn, idp2_arn)])

        assert SamlAssertion(assertion).roles() == [{'role': dev_arn,
                                                     'principle': idp_arn},
                                                    {'role': qa_arn,
                                                     'principle': idp2_arn}]

    def test_assertion_is_encoded(self):
        test_str = str.encode('test encoding')
        assert SamlAssertion(test_str).encode() == 'dGVzdCBlbmNvZGluZw=='
