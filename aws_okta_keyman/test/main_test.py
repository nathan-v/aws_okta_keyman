from __future__ import unicode_literals

import sys
import unittest

import aws_okta_keyman

if sys.version_info[0] < 3:  # Python 2
    import mock
else:
    from unittest import mock


class MainTest(unittest.TestCase):

    @mock.patch('aws_okta_keyman.__main__.Keyman')
    def test_entry_point_func(self, keyman_mock):
        keyman_mock.main.return_value = None
        with self.assertRaises(SystemExit):
            aws_okta_keyman.__main__.entry_point()

        keyman_mock.assert_has_calls([
            mock.call(mock.ANY),
            mock.call().main()
        ])
