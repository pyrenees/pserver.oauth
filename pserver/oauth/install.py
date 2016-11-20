# -*- coding: utf-8 -*-
from plone.server.addons import Addon
from plone.server import AUTH_USER_PLUGINS
from plone.server import AUTH_EXTRACTION_PLUGINS
from plone.server.registry import ILayers
from pserver.oauth.oauth import PloneJWTExtraction
from pserver.oauth.oauth import OAuthPloneUserFactory

POAUTH_LAYER = 'pserver.oauth.interfaces.IPOAuthLayer'

AUTH_USER_PLUGINS.append(OAuthPloneUserFactory)
AUTH_EXTRACTION_PLUGINS.append(PloneJWTExtraction)


class POauthAddon(Addon):

    @classmethod
    def install(self, request):
        registry = request.site_settings
        registry.forInterface(ILayers).active_layers |= {
            POAUTH_LAYER
        }

    @classmethod
    def uninstall(self, request):
        registry = request.site_settings
        registry.forInterface(ILayers).active_layers -= {
            POAUTH_LAYER
        }
