# -*- coding: utf-8 -*-

from plone.server.testing import PloneBaseLayer
import unittest


OAUTH_UTILITY_CONFIG = {
    'provides': 'pserver.oauth.oauth.IOAuth',
    'factory': 'pserver.oauth.oauth.OAuth',
    'settings': {
        'server': 'http://localhost/',
        'jwt_secret': 'secret',
        'jwt_algorithm': 'HS256',
        'client_id': 11,
        'client_password': 'secret'
    }
}


class PloneOAuthLayer(PloneBaseLayer):

    @classmethod
    def setUp(cls):
        cls.app.add_async_utility(OAUTH_UTILITY_CONFIG)

    @classmethod
    def testSetUp(cls):
        pass

    @classmethod
    def testTearDown(cls):
        pass

    @classmethod
    def tearDown(cls):
        cls.app.del_async_utility(OAUTH_UTILITY_CONFIG)


class PloneOAuthServerTestCase(unittest.TestCase):
    ''' Adding the OAuth utility '''
    layer = PloneOAuthLayer
