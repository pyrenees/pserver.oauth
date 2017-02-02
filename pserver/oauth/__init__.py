# -*- coding: utf-8 -*-
from plone.server import configure


def includeme(root):
    configure.permission('plone.GetOAuthGrant', 'Get OAuth Grant Code')
    configure.grant(
        permission="plone.GetOAuthGrant",
        role="plone.Anonymous")
    from . import oauth  # noqa
