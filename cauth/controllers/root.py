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
import logging

from pecan import expose, response, conf, abort, render
from pecan.rest import RestController

from cauth.backends import githubauth, localauth, ldapauth
from cauth.utils import common


LOGOUT_MSG = "You have been successfully logged " \
             "out of all the Software factory services."

logger = logging.getLogger(__name__)


class LoginController(RestController):
    def check_valid_user(self, username, password):
        user = conf.auth.get('users', {}).get(username)
        if user:
            salted_password = user.get('password')
            if salted_password == crypt.crypt(password, salted_password):
                return user.get('mail'), user.get('lastname'), []

        localdb = conf.auth.get('localdb')
        if localdb:
            return localauth.check_localdb_user(localdb, username, password)

        ldap = conf.auth.get('ldap')
        if ldap:
            return ldapauth.check_ldap_user(ldap, username, password)

        logger.error('User not authenticated')
        return None

    @expose()
    def post(self, **kwargs):
        logger.info('Client requests authentication.')
        if 'back' not in kwargs:
            logger.error('Client requests authentication without back url.')
            abort(422)
        back = kwargs['back']
        if 'username' in kwargs and 'password' in kwargs:
            username = kwargs['username']
            password = kwargs['password']
            valid_user = self.check_valid_user(username, password)
            if not valid_user:
                logger.error('Client requests authentication with wrong'
                             ' credentials.')
                response.status = 401
                return render('login.html',
                              dict(back=back, message='Authorization failed.'))
            email, lastname, sshkey = valid_user
            logger.info('Client requests authentication success %s' % username)
            common.setup_response(username, back, email, lastname, sshkey)
        else:
            logger.error('Client requests authentication without credentials.')
            response.status = 401
            return render('login.html', dict(back=back,
                                             message='Authorization failed.'))

    @expose(template='login.html')
    def get(self, **kwargs):
        if 'back' not in kwargs:
            kwargs['back'] = '/auth/logout'

        logger.info('Client requests the login page.')
        return dict(back=kwargs["back"], message='')

    github = githubauth.GithubController()
    githubAPIkey = githubauth.PersonalAccessTokenGithubController()


class LogoutController(RestController):
    @expose(template='login.html')
    def get(self, **kwargs):
        response.delete_cookie('auth_pubtkt', domain=conf.app.cookie_domain)
        return dict(back='/', message=LOGOUT_MSG)


class RootController(object):
    login = LoginController()
    logout = LogoutController()
