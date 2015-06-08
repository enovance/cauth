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

import ldap
import logging

logger = logging.getLogger(__name__)


def check_ldap_user(config, username, password):
    try:
        conn = ldap.initialize(config['host'])
        conn.set_option(ldap.OPT_REFERRALS, 0)
    except ldap.LDAPError:
        logger.error('Client unable to bind on LDAP unexpected behavior.')
        return None

    who = config['dn'] % {'username': username}
    try:
        conn.simple_bind_s(who, password)
    except (ldap.INVALID_CREDENTIALS, ldap.SERVER_DOWN):
        logger.error('Client unable to bind on LDAP invalid credentials.')
        return None

    result = conn.search_s(who, ldap.SCOPE_SUBTREE, '(cn=*)',
                           attrlist=[config['sn'], config['mail']])
    if len(result) == 1:
        user = result[0]  # user is a tuple
        mail = user[1].get(config['mail'], [None])
        lastname = user[1].get(config['sn'], [None])
        return mail[0], lastname[0], []

    logger.error('LDAP client search failed')
    return None
