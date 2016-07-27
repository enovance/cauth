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

import logging

from pecan import expose, response, conf, abort, render
from stevedore import driver

from cauth.auth import base
from cauth.model import db
from cauth.utils import common


logger = logging.getLogger(__name__)


OAUTH_PROVIDERS_PLUGINS=['github', ]


class OAuth2Controller(object):
    def __init__(self):
        plugin = None
        for p in OAUTH_PROVIDERS_PLUGINS:
            try:
                plugin = driver.DriverManager(
                    namespace='cauth.authentication',
                    name=p,
                    invoke_on_load=True,
                    invoke_args=(conf,)).driver
                # load the first one, we frown upon multiple providers at once
                break
            except:
                pass
        if plugin:
            self.auth_plugin = plugin
        else:
            msg = ('no valid configuration found for any of the '
                   'supported OAuth '
                   'providers (%s)' % ', '.join(OAUTH_PROVIDERS_PLUGINS))
            raise base.AuthProtocolNotAvailableError(msg)
               

    @expose()
    def callback(self, **kwargs):
        auth_context = kwargs
        auth_context['response'] = kwargs
        auth_context['calling_back'] = True
        try:
            # Verify the state previously put in the db
            state = auth_context.get('state', None)
            back = db.get_url(state)
            if not back:
                err = 'OAuth callback with forged state, discarding'
                logger.debug(err)
                raise base.UnauthenticatedError(err)
            auth_context['back'] = back
            valid_user = self.auth_plugin.authenticate(**auth_context)
        except base.UnauthenticatedError as e:
            response.status = 401
            auth_methods = [k for k, v in conf.get('auth', {})]
            return render('login.html',
                          dict(back=back,
                               message='Authorization failure: %s' % e,
                               auth_methods=auth_methods))
        logger.info(
            '%s (%s) successfully authenticated with OAuth2.'
            % (valid_user['login'], valid_user['email']))
        common.setup_response(valid_user,
                              back)

    @expose()
    def index(self, **kwargs):
        auth_context = kwargs
        auth_context['response'] = response
        # we don't expect a return value, we set up the redirect here
        self.auth_plugin.authenticate(**auth_context)
