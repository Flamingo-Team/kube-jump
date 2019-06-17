# ~*~ coding: utf-8 ~*~
from __future__ import unicode_literals

from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls.i18n import i18n_patterns
from django.views.i18n import JavaScriptCatalog

from .views import IndexView, LunaView, I18NView
from .swagger import get_swagger_view


api_v1_patterns = [
   path('api/', include([
        path('users/v1/', include('users.urls.api_urls', namespace='api-users')),
        path('k8s/v1/', include('k8s.urls.api_urls', namespace='api-k8s')),
        path('assets/v1/', include('assets.urls.api_urls', namespace='api-assets')),
        path('perms/v1/', include('perms.urls.api_urls', namespace='api-perms')),
        path('terminal/v1/', include('terminal.urls.api_urls', namespace='api-terminal')),
        path('ops/v1/', include('ops.urls.api_urls', namespace='api-ops')),
        path('audits/v1/', include('audits.urls.api_urls', namespace='api-audits')),
        path('orgs/v1/', include('orgs.urls.api_urls', namespace='api-orgs')),
        path('common/v1/', include('common.urls.api_urls', namespace='api-common')),
   ]))
]

api_v2_patterns = [
    path('api/', include([
        path('terminal/v2/', include('terminal.urls.api_urls_v2', namespace='api-terminal-v2')),
        path('users/v2/', include('users.urls.api_urls_v2', namespace='api-users-v2')),
    ]))
]

app_view_patterns = [
    path('users/', include('users.urls.views_urls', namespace='users')),
    path('assets/', include('assets.urls.views_urls', namespace='assets')),
    path('perms/', include('perms.urls.views_urls', namespace='perms')),
    path('terminal/', include('terminal.urls.views_urls', namespace='terminal')),
    path('ops/', include('ops.urls.view_urls', namespace='ops')),
    path('audits/', include('audits.urls.view_urls', namespace='audits')),
    path('orgs/', include('orgs.urls.views_urls', namespace='orgs')),
    path('auth/', include('authentication.urls.view_urls'), name='auth'),
]


if settings.XPACK_ENABLED:
    app_view_patterns.append(path('xpack/', include('xpack.urls', namespace='xpack')))

js_i18n_patterns = i18n_patterns(
    path('jsi18n/', JavaScriptCatalog.as_view(), name='javascript-catalog'),
)

urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    path('', include(api_v2_patterns)),
    path('', include(api_v1_patterns)),
    path('luna/', LunaView.as_view(), name='luna-error'),
    path('i18n/<str:lang>/', I18NView.as_view(), name='i18n-switch'),
    path('settings/', include('common.urls.view_urls', namespace='settings')),
    path('common/', include('common.urls.view_urls', namespace='common')),
    # path('api/v2/', include(api_v2_patterns)),

    # External apps url
    path('captcha/', include('captcha.urls')),
]
urlpatterns += app_view_patterns
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) \
            + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += js_i18n_patterns

if settings.DEBUG:
    urlpatterns += [
        re_path('^swagger(?P<format>\.json|\.yaml)$',
                get_swagger_view().without_ui(cache_timeout=1), name='schema-json'),
        path('docs/', get_swagger_view().with_ui('swagger', cache_timeout=1), name="docs"),
        path('redoc/', get_swagger_view().with_ui('redoc', cache_timeout=1), name='redoc'),

        re_path('^v2/swagger(?P<format>\.json|\.yaml)$',
                get_swagger_view().without_ui(cache_timeout=1), name='schema-json'),
        path('docs/v2/', get_swagger_view("v2").with_ui('swagger', cache_timeout=1), name="docs"),
        path('redoc/v2/', get_swagger_view("v2").with_ui('redoc', cache_timeout=1), name='redoc'),
    ]
