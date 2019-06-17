#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

from __future__ import unicode_literals

from django.db import models
import logging
from django.utils.translation import ugettext_lazy as _


__all__ = ['K8sKeyInfo']
logger = logging.getLogger(__name__)


class K8sKeyInfo(models.Model):


    # Important
    assets_system_user = models.CharField(max_length=128, verbose_name=_("Asset System User"))
    docker_ip = models.GenericIPAddressField(max_length=32, verbose_name=_('Docker IP'), db_index=True)
    k8s_api = models.CharField(max_length=128, verbose_name=_('K8S API'))
    k8s_user_name = models.CharField(max_length=128, verbose_name=_('K8S user name'))
    k8s_passwd = models.CharField(max_length=128, verbose_name=_('K8S passwd'))
    k8s_system = models.CharField(max_length=128, verbose_name=_('K8S system or namespace'))
    k8s_pod_name = models.CharField(max_length=128, verbose_name=_('K8S pod name'))
    comment = models.TextField(blank=True, verbose_name=_('Comment'))
    date_created = models.DateTimeField(
        auto_now_add=True, verbose_name=_('Date created'))
    created_by = models.CharField(max_length=32, null=True, blank=True, verbose_name=_('Created by'))

    def __unicode__(self):
        return '%s-%s-%s-%s' % (self.k8s_api, self.k8s_user_name, self.k8s_passwd, self.k8s_system)
    __str__ = __unicode__

    @property
    def is_valid(self):
        warning = ''
        if not self.is_active:
            warning += ' inactive'
        else:
            return True, ''
        return False, warning

    def to_json(self):
        return {
            'assets_system_user': self.assets_system_user,
            'k8s_api': self.k8s_api,
            'k8s_user_name': self.k8s_user_name,
            'k8s_passwd': self.k8s_passwd,
        }

    class Meta:
        unique_together = ('assets_system_user', 'k8s_api')

    @classmethod
    def generate_fake(cls, count=100):
        from random import seed, choice
        import forgery_py
        from django.db import IntegrityError

        seed()
        for i in range(count):
            k8s_key_info = cls(docker_ip='%s.%s.%s.%s' % (i, i, i, i),
                               k8s_api='k8s_api',
                               k8s_user_name='k8s_user_name',
                               k8s_passwd='k8s_passwd',
                               k8s_system='k8s_system',
                               k8s_pod_name='k8s_pod_name',
                               assets_system_user='assets_system_user',
                               created_by='Fake')
            try:
                k8s_key_info.save()
                k8s_key_info.assets_system_user = 'dd'
                k8s_key_info.k8s_pod_name = 'name'
                logger.debug('Generate fake asset : %s' % k8s_key_info.docker_ip)
            except IntegrityError:
                print('Error continue')
                continue

