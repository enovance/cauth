#!/usr/bin/env python
#
# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import crypt
import urllib
import logging
import requests

from basicauth import encode

logger = logging.getLogger(__name__)


def check_static_user(config, username, password):
    user = config.auth.get('users', {}).get(username)
    if user:
        salted_password = user.get('password')
        if salted_password == crypt.crypt(password, salted_password):
            return user.get('mail'), user.get('lastname'), []


def check_db_user(config, username, password):
    localdb = config.auth.get('localdb')
    if localdb:
        bind_url = urllib.basejoin(localdb['managesf_url'], '/manage/bind')
        headers = {"Authorization": encode(username, password)}
        response = requests.get(bind_url, headers=headers)

        if response.status_code > 399:
            logger.error('localdb auth failed: %s' % response)
            return None
        infos = response.json()
        return infos['email'], infos['fullname'], [{'key': infos['sshkey']}, ]
