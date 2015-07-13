#!/usr/bin/env python
#
# Copyright (C) 2015 eNovance SAS <licensing@enovance.com>
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
import requests
from pecan import request
from requests.exceptions import ConnectionError
import urllib

from cauth.auth import base
from cauth.model import db


"""OpenID authentication plugins."""


logger = logging.getLogger(__name__)


class OpenIDAuthPlugin(base.AuthProtocolPlugin):

    _config_section = "openid"

    @classmethod
    def get_args(cls):
        return {}

    def authenticate(self, **auth_context):
        if auth_context.get('calling_back', False):
            return self._authenticate(**auth_context)
        else:
            back = auth_context['back']
            response = auth_context['response']
            self.redirect(back, response)

    def redirect(self, back, response):
        """Send the user to the OpenID auth page"""
        params = {'back': back}
        response.status_code = 302
        return_to = request.host_url + self.conf['redirect_uri'] 
        return_to += "?" + urllib.urlencode(params)
        openid_params = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "checkid_setup",

            "openid.claimed_id": "http://specs.openid.net/auth/2.0/"
                                 "identifier_select",
            "openid.identity": "http://specs.openid.net/auth/2.0/"
                               "identifier_select",

            "openid.realm": request.host_url,
            "openid.return_to": return_to,

            "openid.ns.sreg": "http://openid.net/sreg/1.0",
            "openid.sreg.required": "nickname,fullname,email",

            "openid.ns.ext2": "http://openid.net/srv/ax/1.0",
            "openid.ext2.mode": "fetch_request",
            "openid.ext2.type.FirstName": "http://schema.openid.net/"
                                          "namePerson/first",
            "openid.ext2.type.LastName": "http://schema.openid.net/"
                                         "namePerson/last",
            "openid.ext2.type.Email": "http://schema.openid.net/contact/email",
            "openid.ext2.type.Alias": "http://schema.openid.net/"
                                      "namePerson/friendly",
            "openid.ext2.required": "Alias,FirstName,LastName,Email"
        }
        
        response.location = self.conf['auth_url'] + "?" + \
            urllib.urlencode(openid_params)

    def _authenticate(**auth_context):
        """Called at the callback level"""
        raise base.UnauthenticatedError("Not implemented yet")
        logger.info(
            'Client %s (%s) authenticated through OpenID'
            % (login, email))
        return {'login': login,
                'email': email,
                'name': name,
                'ssh_keys': ssh_keys}
