#!/usr/bin/env python

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
# Copyright 2018 Nextdoor.com, Inc
# Copyright 2018 Nathan V
"""Main function that passes off to the Keyman module."""

from __future__ import unicode_literals

import logging
import sys

import colorlog

from aws_okta_keyman.keyman import Keyman


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = colorlog.StreamHandler()
    fmt = (
        '%(asctime)-8s (%(bold)s%(log_color)s%(levelname)s%(reset)s) '
        '%(message)s')
    formatter = colorlog.ColoredFormatter(fmt, datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    keyman = Keyman(sys.argv)
    raise SystemExit(keyman.main())


if __name__ == '__main__':
    entry_point()
