# -*- coding: utf-8 -*-
#
from collections import OrderedDict
import logging
import uuid

from django.core.cache import cache
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.views import APIView, Response
from rest_framework.permissions import AllowAny


from common.utils import get_object_or_none
from common.permissions import IsAppUser, IsOrgAdminOrAppUser, IsSuperUser
from ...models import Terminal, Status, Session
from ...serializers import v1 as serializers

__all__ = [
    'TerminalViewSet', 'TerminalTokenApi', 'StatusViewSet', 'TerminalConfig',
]
logger = logging.getLogger(__file__)


class TerminalViewSet(viewsets.ModelViewSet):
    queryset = Terminal.objects.filter(is_deleted=False)
    serializer_class = serializers.TerminalSerializer
    permission_classes = (IsSuperUser,)

    def create(self, request, *args, **kwargs):
        name = request.data.get('name')
        remote_ip = request.META.get('REMOTE_ADDR')
        x_real_ip = request.META.get('X-Real-IP')
        remote_addr = x_real_ip or remote_ip

        terminal = get_object_or_none(Terminal, name=name, is_deleted=False)
        if terminal:
            msg = 'Terminal name %s already used' % name
            return Response({'msg': msg}, status=409)

        serializer = self.serializer_class(data={
            'name': name, 'remote_addr': remote_addr
        })

        if serializer.is_valid():
            terminal = serializer.save()

            # App should use id, token get access key, if accepted
            token = uuid.uuid4().hex
            cache.set(token, str(terminal.id), 3600)
            data = {"id": str(terminal.id), "token": token, "msg": "Need accept"}
            return Response(data, status=201)
        else:
            data = serializer.errors
            logger.error("Register terminal error: {}".format(data))
            return Response(data, status=400)

    def get_permissions(self):
        if self.action == "create":
            self.permission_classes = (AllowAny,)
        return super().get_permissions()


class TerminalTokenApi(APIView):
    permission_classes = (AllowAny,)
    queryset = Terminal.objects.filter(is_deleted=False)

    def get(self, request, *args, **kwargs):
        try:
            terminal = self.queryset.get(id=kwargs.get('terminal'))
        except Terminal.DoesNotExist:
            terminal = None

        token = request.query_params.get("token")

        if terminal is None:
            return Response('May be reject by administrator', status=401)

        if token is None or cache.get(token, "") != str(terminal.id):
            return Response('Token is not valid', status=401)

        if not terminal.is_accepted:
            return Response("Terminal was not accepted yet", status=400)

        if not terminal.user or not terminal.user.access_key:
            return Response("No access key generate", status=401)

        access_key = terminal.user.access_key()
        data = OrderedDict()
        data['access_key'] = {'id': access_key.id, 'secret': access_key.secret}
        return Response(data, status=200)


class StatusViewSet(viewsets.ModelViewSet):
    queryset = Status.objects.all()
    serializer_class = serializers.StatusSerializer
    permission_classes = (IsOrgAdminOrAppUser,)
    session_serializer_class = serializers.SessionSerializer
    task_serializer_class = serializers.TaskSerializer

    def create(self, request, *args, **kwargs):
        from_gua = self.request.query_params.get("from_guacamole", None)
        if not from_gua:
            self.handle_sessions()
        super().create(request, *args, **kwargs)
        tasks = self.request.user.terminal.task_set.filter(is_finished=False)
        serializer = self.task_serializer_class(tasks, many=True)
        return Response(serializer.data, status=201)

    def handle_sessions(self):
        sessions_active = []
        for session_data in self.request.data.get("sessions", []):
            self.create_or_update_session(session_data)
            if not session_data["is_finished"]:
                sessions_active.append(session_data["id"])

        sessions_in_db_active = Session.objects.filter(
            is_finished=False,
            terminal=self.request.user.terminal.id
        )

        for session in sessions_in_db_active:
            if str(session.id) not in sessions_active:
                session.is_finished = True
                session.date_end = timezone.now()
                session.save()

    def create_or_update_session(self, session_data):
        session_data["terminal"] = self.request.user.terminal.id
        _id = session_data["id"]
        session = get_object_or_none(Session, id=_id)
        if session:
            serializer = serializers.SessionSerializer(
                data=session_data, instance=session
            )
        else:
            serializer = serializers.SessionSerializer(data=session_data)

        if serializer.is_valid():
            session = serializer.save()
            return session
        else:
            msg = "session data is not valid {}: {}".format(
                serializer.errors, str(serializer.data)
            )
            logger.error(msg)
            return None

    def get_queryset(self):
        terminal_id = self.kwargs.get("terminal", None)
        if terminal_id:
            terminal = get_object_or_404(Terminal, id=terminal_id)
            self.queryset = terminal.status_set.all()
        return self.queryset

    def perform_create(self, serializer):
        serializer.validated_data["terminal"] = self.request.user.terminal
        return super().perform_create(serializer)

    def get_permissions(self):
        if self.action == "create":
            self.permission_classes = (IsAppUser,)
        return super().get_permissions()


class TerminalConfig(APIView):
    permission_classes = (IsAppUser,)

    def get(self, request):
        user = request.user
        terminal = user.terminal
        configs = terminal.config
        return Response(configs, status=200)