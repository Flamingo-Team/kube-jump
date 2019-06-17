# ~*~ coding: utf-8 ~*~
import datetime

from django.utils import timezone

from .base import CommandBase


class CommandStore(CommandBase):

    def __init__(self, params):
        from terminal.models import Command
        self.model = Command

    def save(self, command):
        """
        保存命令到数据库
        """

        self.model.objects.create(
            user=command["user"], asset=command["asset"],
            system_user=command["system_user"], input=command["input"],
            output=command["output"], session=command["session"],
            org_id=command["org_id"], timestamp=command["timestamp"]
        )

    def bulk_save(self, commands):
        """
        批量保存命令到数据库, command的顺序和save中一致
        """
        _commands = []
        for c in commands:
            _commands.append(self.model(
                user=c["user"], asset=c["asset"], system_user=c["system_user"],
                input=c["input"], output=c["output"], session=c["session"],
                org_id=c["org_id"], timestamp=c["timestamp"]
            ))
        return self.model.objects.bulk_create(_commands)

    @staticmethod
    def make_filter_kwargs(
            date_from=None, date_to=None,
            user=None, asset=None, system_user=None,
            input=None, session=None):
        filter_kwargs = {}
        date_from_default = timezone.now() - datetime.timedelta(days=7)
        date_to_default = timezone.now()

        date_from = date_from if date_from else date_from_default
        date_to = date_to if date_to else date_to_default
        filter_kwargs['timestamp__gte'] = int(date_from.timestamp())
        filter_kwargs['timestamp__lte'] = int(date_to.timestamp())

        if user:
            filter_kwargs["user"] = user
        if asset:
            filter_kwargs['asset'] = asset
        if system_user:
            filter_kwargs['system_user'] = system_user
        if input:
            filter_kwargs['input__icontains'] = input
        if session:
            filter_kwargs['session'] = session

        return filter_kwargs

    def filter(self, date_from=None, date_to=None,
               user=None, asset=None, system_user=None,
               input=None, session=None):
        filter_kwargs = self.make_filter_kwargs(
            date_from=date_from, date_to=date_to, user=user,
            asset=asset, system_user=system_user, input=input,
            session=session,
        )
        queryset = self.model.objects.filter(**filter_kwargs)
        return queryset

    def count(self, date_from=None, date_to=None,
              user=None, asset=None, system_user=None,
              input=None, session=None):
        filter_kwargs = self.make_filter_kwargs(
            date_from=date_from, date_to=date_to, user=user,
            asset=asset, system_user=system_user, input=input,
            session=session,
        )
        count = self.model.objects.filter(**filter_kwargs).count()
        return count


