# -*- coding: utf-8 -*-
from pserver.oauth.oauth import IOAuth
from pserver.oauth.testing import PloneOAuthServerTestCase
from zope.component import getUtility


class TestTraversal(PloneOAuthServerTestCase):

    def test_auth_registered(self):
        self.assertTrue(getUtility(IOAuth) is not None)
