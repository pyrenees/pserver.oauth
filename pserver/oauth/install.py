# -*- coding: utf-8 -*-
from plone.server.addons import Addon
from plone.server.registry import IAuthExtractionPlugins
from plone.server.registry import IAuthPloneUserPlugins
from plone.server.registry import ILayers


AUTH_EXTRACTION_PLUGIN = 'pserver.oauth.oauth.PloneJWTExtraction'
AUTH_PLONE_FACTORY_PLUGIN = 'pserver.oauth.oauth.OAuthPloneUserFactory'
POAUTH_LAYER = 'pserver.oauth.interfaces.IPOAuthLayer'


class POauthAddon(Addon):

    @classmethod
    def install(self, request):
        registry = request.site_settings
        registry.forInterface(ILayers).active_layers |= {
            POAUTH_LAYER
        }
        registry.forInterface(IAuthExtractionPlugins).active_plugins |= {
            AUTH_EXTRACTION_PLUGIN
        }
        registry.forInterface(IAuthPloneUserPlugins).active_plugins |= {
            AUTH_PLONE_FACTORY_PLUGIN
        }

    @classmethod
    def uninstall(self, request):
        registry = request.site_settings
        registry.forInterface(ILayers).active_layers -= {
            POAUTH_LAYER
        }
        registry.forInterface(IAuthExtractionPlugins).active_plugins -= {
            AUTH_EXTRACTION_PLUGIN
        }
        registry.forInterface(IAuthPloneUserPlugins).active_plugins -= {
            AUTH_PLONE_FACTORY_PLUGIN
        }
