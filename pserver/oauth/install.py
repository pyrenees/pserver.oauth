# -*- coding: utf-8 -*-
from plone.server.addons import Addon
from plone.server.registry import ILayers
from plone.server import configure

POAUTH_LAYER = 'pserver.oauth.interfaces.IPOAuthLayer'


@configure.addon(
    name="poauth",
    title="Plone OAuth Login")
class POauthAddon(Addon):

    @classmethod
    def install(cls, site, request):
        registry = request.site_settings
        registry.forInterface(ILayers).active_layers |= {
            POAUTH_LAYER
        }

    @classmethod
    def uninstall(cls, site, request):
        registry = request.site_settings
        registry.forInterface(ILayers).active_layers -= {
            POAUTH_LAYER
        }
