from __future__ import unicode_literals

import unittest

from aws_okta_keyman import metadata


class MetadataTest(unittest.TestCase):

    def test_version(self):
        assert metadata.__version__

    def test_init_blank_args(self):
        assert metadata.__desc__
