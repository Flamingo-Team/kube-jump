# -*- coding: utf-8 -*-
#
from rest_framework import viewsets

from common.permissions import IsValidUser
from ..models import CommandExecution
from ..serializers import CommandExecutionSerializer
from ..tasks import run_command_execution


class CommandExecutionViewSet(viewsets.ModelViewSet):
    serializer_class = CommandExecutionSerializer
    permission_classes = (IsValidUser,)
    task = None

    def get_queryset(self):
        return CommandExecution.objects.filter(
            user_id=str(self.request.user.id)
        )

    def perform_create(self, serializer):
        instance = serializer.save()
        instance.user = self.request.user
        instance.save()
        run_command_execution.apply_async(
            args=(instance.id,), task_id=str(instance.id)
        )
