# -*- coding: utf-8 -*-
from plone.server.addons import Addon
from plone.server.registry import ILayers

POAUTH_LAYER = 'pserver.oauth.interfaces.IPOAuthLayer'


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
