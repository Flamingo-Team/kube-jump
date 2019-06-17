# -*- coding: utf-8 -*-

import os

from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jumpserver.settings')

from django.conf import settings

app = Celery('jumpserver')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(lambda: [app_config.split('.')[0] for app_config in settings.INSTALLED_APPS])
