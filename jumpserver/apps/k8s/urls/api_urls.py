#!/usr/bin/env python
# ~*~ coding: utf-8 ~*~
#
from __future__ import absolute_import

from django.urls import path
from rest_framework_bulk.routes import BulkRouter
from .. import api


app_name = 'k8s'

router = BulkRouter()

urlpatterns = [
    path('apply', api.erp_binding, name='erp-binding'),
    path('master', api.master_auth, name='master-auth'),
    path('apply/reload', api.reload_sercret_key, name='reload-key'),
    # url(r'^v2/k8s$', api.erp_binding_ips),
    # url(r'^v1/k8s/reload$', api.reload_sercret_key),
    # url(r'^v1/k8s$', api.erp_binding),
    # url(r'^ad$', api.erp_binding_ad),
    #url(r'^v1/k8s/appname/(?P<appname>[0-20]+)$', views.query),
]

urlpatterns += router.urls
