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


__version__ = '0.2.1'
__desc__ = 'AWS Okta Keyman'
__desc_long__ = ('''
===============
AWS Okta Keyman
===============
AWS Okta Keyman is a command-line interface for retrieving temporary
credentials from AWS for use during development. It authenticates with Okta
and then retrieves keys from AWS. These are saved in ~/aws/credentials for
use with other software. AWS Okta Keyman supports Okta Verify and Duo Auth
for MFA.

It's based on `nd_okta_auth <http://github.com/Nextdoor/nd_okta_auth>`_
by `Nextdoor.com, Inc <https://github.com/Nextdoor>`_.

For more information check out the source on
`Github <https://github.com/nathan-v/aws_okta_keyman>`_.''')
