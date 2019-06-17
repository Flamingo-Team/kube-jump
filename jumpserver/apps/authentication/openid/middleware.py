# coding:utf-8
#

from django.conf import settings
from django.contrib.auth import logout
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import BACKEND_SESSION_KEY

from . import client
from common.utils import get_logger
from .backends import BACKEND_OPENID_AUTH_CODE
from authentication.openid.models import OIDT_ACCESS_TOKEN

logger = get_logger(__file__)


class OpenIDAuthenticationMiddleware(MiddlewareMixin):
    """
    Check openid user single logout (with access_token)
    """

    def process_request(self, request):

        # Don't need openid auth if AUTH_OPENID is False
        if not settings.AUTH_OPENID:
            return

        # Don't need check single logout if user not authenticated
        if not request.user.is_authenticated:
            return

        elif request.session[BACKEND_SESSION_KEY] != BACKEND_OPENID_AUTH_CODE:
            return

        # Check openid user single logout or not with access_token
        try:
            client.openid_connect_client.userinfo(
                token=request.session.get(OIDT_ACCESS_TOKEN))

        except Exception as e:
            logout(request)
            logger.error(e)
