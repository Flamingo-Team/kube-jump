# -*- coding: utf-8 -*-
from __future__ import unicode_literals


from rest_framework.response import Response
from django.http import HttpResponse
from django.conf import settings


from .hands import User, UserGroup, Asset, \
    AdminUser, SystemUser, AssetPermission


from .models import K8sKeyInfo
from django.views.decorators.csrf import csrf_exempt
import json
from random import choice
import string

from django.utils import timezone
from common.utils import ssh_key_gen, ssh_pubkey_gen, get_logger
# from common.utils import validate_ssh_private_key, ssh_pubkey_gen, get_logger
import re
from Crypto.Cipher import AES
import base64
from kubernetes.client import Configuration
from kubernetes.client.apis import core_v1_api
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from users import authentication

import paramiko
from io import StringIO


logger = get_logger(__file__)

TIMEOUT=20

def GenPassword(length=8,
                chars=string.ascii_letters + string.digits):
    return ''.join([choice(chars) for i in range(length)])


class prpcrypt():
    def __init__(self, key=b'whGcZugH\0\0\0\0\0\0\0\0', iv=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'):
        self.key = key
        self.mode = AES.MODE_ECB
        self.iv = iv
        BS = AES.block_size
        self.PADDING = chr(8)
        self.pad = lambda s: s + (BS - len(s) % BS) * self.PADDING  # chr(BS - len(s) % BS)
        self.unpad = lambda s: s[0:-ord(s[-1])]

    def encrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        crypt = generator.encrypt(self.pad(text))
        # crypt = generator.encrypt(text)
        cryptedStr = base64.b64encode(crypt)
        return cryptedStr.decode("utf-8").rstrip(self.PADDING)

    def decrypt(self, text):
        generator = AES.new(self.key, self.mode, self.iv)
        cryptedStr = base64.b64decode(text)
        recovery = generator.decrypt(cryptedStr)
        return recovery.decode("utf-8").rstrip(self.PADDING)


def k8s_exec_command(k8s_api, k8s_username, k8s_passwd, namespace, pod_name, cmd):
    try:
        c = Configuration()
        c.host = k8s_api
        c.username = k8s_username
        c.password = k8s_passwd
        logger.info("k8s pw %s" % k8s_passwd)
        logger.info("k8s head:" +k8s_api+";"+k8s_username+";"+namespace+";"+k8s_passwd+";")
        c.api_key['authorization'] = c.get_basic_auth_token()
        c.verify_ssl = False
        Configuration.set_default(c)
        api = core_v1_api.CoreV1Api()
        resp = None
        try:
            resp = api.read_namespaced_pod(name=pod_name,
                                           namespace=namespace)
        except ApiException as e:
            if e.status != 404:
                logger.warning("Unknown error: %s" % e)
                return 500, "Unknown error: %s" % e
            else:
                logger.warning("Pod %s does not exits." % pod_name)
                return 404, "Pod %s does not exits." % pod_name

        if not resp:
            logger.warning("Pod %s does not exits." % pod_name)
            return 404, "Pod %s does not exits." % pod_name

        cmd[-1] += "; echo success"
        logger.info("k8s_exec_command: %s" % cmd[-1])

        resp = stream(api.connect_get_namespaced_pod_exec, pod_name, namespace,
                      command=cmd,
                      stderr=True, stdin=False,
                      stdout=True, tty=False, _request_timeout=TIMEOUT)
        # resp.update(timeout=1)
        logger.info("Response: " + resp)
        if resp:
            return 200, "Response: " + resp
        else:
            return 500, "exec cmd timeout"
    except Exception as e:
        logger.info(e)
        return 500, "Unknown error: %s" % e


def checkip(ip):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(ip):
        return True
    else:
        return False




class PKey(object):
    @classmethod
    def from_string(cls, key_string):
        try:
            pkey = paramiko.RSAKey(file_obj=StringIO(key_string))
            return pkey
        except paramiko.SSHException:
            try:
                pkey = paramiko.DSSKey(file_obj=StringIO(key_string))
                return pkey
            except paramiko.SSHException:
                return None


def k8s_exec_command_with_ip(k8s_api, k8s_username, namespace, k8s_passwd, ip, cmd):
    c = Configuration()
    c.host = k8s_api
    c.username = k8s_username
    k8s_passwd = prpcrypt().decrypt(k8s_passwd)
    c.password = k8s_passwd
    c.api_key['authorization'] = c.get_basic_auth_token()
    c.verify_ssl = False
    Configuration.set_default(c)
    api = core_v1_api.CoreV1Api()
    try:
        ret = None
        try:
            ret = api.list_namespaced_pod(namespace)
        except ApiException as e:
            if e.status != 404:
                logger.warning("Unknown error: %s" % e)
                return 500, "Unknown error: %s" % e
        pod_name = None
        cmd[-1] += "; echo success"
        for i in ret.items:
            pod_name = i.metadata.name
            if i.status.pod_ip == ip:
                logger.info("k8s: cmd : %s" % cmd)
                resp = stream(api.connect_get_namespaced_pod_exec,
                              i.metadata.name,
                              namespace,
                              command=cmd,
                              stderr=False, stdin=False,
                              stdout=True, tty=False, _request_timeout=TIMEOUT)
                logger.info("Response: " + resp + i.status.pod_ip)
                if resp.strip() == "success":
                    return 200, "Response: " + resp
                else:
                    return 500, "timeout: " + resp
            else:
                # pod_name = i.metadata.name
                continue
        '''
        resp = stream(api.connect_get_namespaced_pod_exec,
                              pod_name,
                              namespace,
                              command=cmd,
                              stderr=False, stdin=False,
                              stdout=True, tty=False, _request_timeout=TIMEOUT)
        logger.info("K8S 404 Response#: " + resp)
        '''
        return 404, "pod not found"
    except Exception as e:
        logger.info(e)
        return 500, "Unknown error: %s" % e
    # logger.info("K8S 404 Response: ")
    # return 404, "pod not found"


def exec_command_with_ip(self, namespace, ip, cmd):
    try:
        ret = self.api.list_namespaced_pod(namespace)
        for i in ret.items:
            if i.status.pod_ip == ip:
                logger.info("K8S: i.metadata.name : %s" % i.metadata.name)
                resp = stream(self.api.connect_get_namespaced_pod_exec,
                              i.metadata.name,
                              namespace,
                              command=cmd,
                              stderr=False, stdin=False,
                              stdout=True, tty=False, _request_timeout=TIMEOUT)
                logger.info("Response: " + resp)
                if resp.strip() == "success":
                    return 200, "Response: " + resp
                else:
                    return 500, "timeout: " + resp
        return 404, "pod not found"
    except Exception as e:
        logger.warning(e)
        return 500, "Unknown error: %s" % e

@csrf_exempt
def reload_sercret_key(request):
    if request.method == 'POST':
        try:
            req = json.loads(request.body)
            logger.info("K8S: reload_sercret_key user: %s" % req['asset'])
            erp = req['user']
            ip = req['asset']
            system_user_name = erp + '_' + ip
            role = req['system_user']
            k8s_key_info = K8sKeyInfo.objects.get(assets_system_user=system_user_name)
            logger.info("K8S: k8s_key_info : %s" % k8s_key_info.k8s_system)
            k8s_api = k8s_key_info.k8s_api
            k8s_user_name = k8s_key_info.k8s_user_name
            k8s_passwd = k8s_key_info.k8s_passwd
            k8s_system = k8s_key_info.k8s_system

            system_user_tuple = SystemUser.objects.filter(name=system_user_name)
            if len(system_user_tuple) != 1:
                return HttpResponse(json.dumps(dict()), content_type="application/json",
                                    reason="system user not found!",
                                    status=404)
            system_user_add = system_user_tuple[0]

            public_key_string = system_user_add.public_key
            private_key_string = system_user_add.private_key
            # logger.info("K8S: k8s_key_info : %s"%private_key_string)
            if role == 'root':
                exec_command = [
                    '/bin/bash',
                    '-c',
                    ROOT_CMD.format(
                        public_key_string, system_user_name)]
            else:
                exec_command = [
                    '/bin/bash',
                    '-c',
                    ADMIN_CMD.format(
                        public_key_string, role, system_user_name)]
            err_reason = ""
            status_code, err_reason = k8s_exec_command_with_ip(k8s_api, k8s_user_name, k8s_system, k8s_passwd, ip, exec_command)
                       
            # logger.info("K8S 404 Response:2 ")
            logger.info("###&&&&& K8S %s %s" % (status_code, err_reason))
            # logger.info("###&&&&&")
            if status_code != 200:
                return HttpResponse(json.dumps(dict()), content_type="application/json", reason=err_reason,
                             status=500) 
            # 验证登陆
            ssh_hello = paramiko.SSHClient()
            try:
                private_key_rsa = PKey.from_string(private_key_string)
                key_str = str(private_key_rsa)
                # logger.info("K8S: **private_key_rsa:%r " % key_str)
                ssh_hello.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                asset_ip = ip
                asset_port = settings.CONFIG.IP_PORT or 22
                logger.info("K8S: **private_key_rsa:%s " % asset_port)
                ssh_hello.connect(hostname=asset_ip,
                                  port=asset_port,
                                  username=role, # system_user_add.username,
                                  pkey=private_key_rsa,
                                  look_for_keys=False,
                                  allow_agent=True,
                                  timeout=10)
                ssh_hello.close()
                logger.info("K8S: *****chenggong: ")
            except (paramiko.AuthenticationException,
                    paramiko.ssh_exception.SSHException):
                msg = 'Connect backend server %s failed: %s' \
                      % (ip, 'Auth failed')
                logger.info(msg)
                ssh_hello.close()
                return HttpResponse({'err_reason': msg}, status=500)
            resp = dict()
            resp['status'] = 201
            resp['msg'] = 'success'
            logger.info("hello world !\n")
            return HttpResponse(json.dumps(resp), content_type="application/json", status=201)
            # return HttpResponse(json.dumps(dict()), content_type="application/json", status=201)
            #return Response({'msg': "success"}, status=201)
        except Exception as e:
            logger.info("###return %s" % e)
            err_rep = dict()
            err_rep['msg'] = 'error'
            logger.warning("K8S: reload_sercret_key request post body is null!")
            return HttpResponse(json.dumps(err_rep), content_type="application/json", status=500)

ADMIN_CMD = "id {1} >& /dev/null; if [ $? -ne 0 ]; then useradd {1}; fi; mkdir -p /home/{1}/.ssh/; touch /home/{1}/.ssh/authorized_keys; sed -i '/{2}/d' /home/{1}/.ssh/authorized_keys; echo {0} >> /home/{1}/.ssh/authorized_keys; chown -R {1}:{1} /home/{1}/.ssh; chmod 700 /home/{1}/.ssh; chmod 600 /home/{1}/.ssh/authorized_keys"
ROOT_CMD = "mkdir -p /root/.ssh/;touch /root/.ssh/authorized_keys; sed -i '/{1}/d' /root/.ssh/authorized_keys; echo {0} >> /root/.ssh/authorized_keys; chmod 644 /root/.ssh/authorized_keys"

@csrf_exempt
def erp_binding(request):
    try:
        if not authentication.PrivateTokenAuthentication().authenticate(request):
            return HttpResponse("%s Authentication failed" % request.user, status=401, content_type="application/json")
    except Exception as e:
        return HttpResponse(reason="Unknown error: %s" % e, status=500, content_type="application/json")

    if request.method == 'POST':
        try:
            req = json.loads(request.body)
            logger.info("K8S request body: %s" % req)
            erp = req['erp']
            ip = req['ip'].rstrip().lstrip()
            is_public = req.get('is_public', 0)
            user_password = req.get('passwd')  # req.get('passwd', GenPassword(16))
            # logger.info("K8S: erp: %s" % erp)
            # k8s parametes
            k8s_api = req['K8sAPI']
            namespace = req['system']
            pod_name = req['podName']
            k8s_username = req["K8sUserName"]
            k8s_passwd = req["K8sPassword"]
            # other parametes
            days = req.get('days', 1)
            role = req.get('role', 'admin')
            # root_erp_list = ['liangxiaolei5']
            # if erp in root_erp_list:
                # role = 'root'
            # auth_mode = req.get('auth_mode', "kube")
            system_user_name = erp + '_' + ip
            k8s_key_info_tuple = K8sKeyInfo.objects.filter(assets_system_user=system_user_name)

            k8s_key_info_tuple.delete()
            k8s_add = K8sKeyInfo.objects.create(assets_system_user=system_user_name, docker_ip=ip, k8s_api=k8s_api,
                                                k8s_user_name=k8s_username,
                                                k8s_passwd=k8s_passwd, k8s_system=namespace, k8s_pod_name=pod_name,
                                                created_by='dd')
            # logger.info("K8S: k8s_add: %s" %str(k8s_add))
            k8s_key_info_tuple = K8sKeyInfo.objects.filter(assets_system_user=system_user_name)
            if len(k8s_key_info_tuple) == 1:
                k8s_key_info_add = k8s_key_info_tuple[0]
            else:
                k8s_key_info_tuple.delete()
                k8s_key_info_add = K8sKeyInfo.objects.create(assets_system_user=system_user_name)
                # logger.info("K8S: k8s_key_info_add.k8s_pod_name: %s" % str(k8s_key_info_add))
            k8s_key_info_add.docker_ip = ip
            k8s_key_info_add.k8s_api = k8s_api
            k8s_key_info_add.k8s_user_name = k8s_username
            k8s_key_info_add.k8s_passwd = k8s_passwd
            k8s_key_info_add.k8s_system = namespace
            k8s_key_info_add.k8s_pod_name = pod_name
            k8s_key_info_add.created_by = 'dd'
            # logger.info("K8S: k8s_key_info_add.k8s_pod_name: %s" % k8s_key_info_add.k8s_pod_name)
            k8s_key_info_add.date_created = timezone.now()
            k8s_key_info_add.save()
        except Exception as e:
            logger.warning("K8S: request post body is null! ip: %s" % ip)
            return HttpResponse(json.dumps(dict()), reason="Unknown error: %s" % e, status=500,
                                content_type="application/json")

        # terminate_connection(d)
        # queryset = ProxyLog.objects.filter(user=erp, terminal='coco', is_finished=False)
        # for proxy_log in queryset:
        #     terminate_connection(proxy_log)
        #     logger.info("K8S: %s is terminated!" % str(proxy_log.id))
        # add user
        user_username = erp
        user_name = erp
        # user_password = GenPassword(15)
        user_email = erp + '@local'
        try:
            userList = User.objects.filter(username=user_username, email=user_email)
            if len(userList) == 1:
                user_add = userList[0]
            elif len(userList) == 0:
                User.objects.filter(username=user_username).delete()
                User.objects.filter(email=user_email).delete()
                user_add = User.objects.create(username=user_username, email=user_email)
            else:
                userList.delete()
                user_add = User.objects.create(username=user_username, email=user_email)
            user_add.name = user_name
            # if user_password == "" or user_password is None:
            #    user_password = GenPassword(16)
            #    if user_add.comment == "" or user_add.comment is None:
            #        user_add.comment = prpcrypt().encrypt(user_password)
            #    else:
            #        user_password = prpcrypt().decrypt(user_add.comment)
            # else:
            #    user_add.comment = prpcrypt().encrypt(user_password)
            # 密码
            user_add.comment = user_password

            cur_password = user_password
            user_add.set_password(cur_password)
            user_add.created_by = erp
            # try:
            #     years = int(settings.CONFIG.USER_EXPIRED_YEARS)
            # except TypeError:
            #     years = 70
            user_expired = timezone.now() + timezone.timedelta(days=365 * 70)
            user_add.date_expired = user_expired
            user_add.save()
        except Exception as e:
            return HttpResponse(json.dumps(dict()), content_type="application/json",
                                reason="Unknown error: %s" % e, status=500)
        logger.info("K8S: user: username:%s,pw:%s added!" % (user_username, cur_password))
        # add system user
        try:
            system_user_name = erp + '_' + ip
            system_user_username = role
            private_key, public_key = ssh_key_gen(username=system_user_name)
            system_user_tuple = SystemUser.objects.filter(name=system_user_name)
            if len(system_user_tuple) == 1:
                system_user_add = system_user_tuple[0]
            else:
                system_user_tuple.delete()
                system_user_add = SystemUser.objects.create(name=system_user_name)
            system_user_add.username = system_user_username
            # system_user_add.password = system_user_password
            # system_user_add.AUTH_METHOD_CHOICES = "K"
            system_user_add.set_auth(password='', private_key=private_key, public_key=public_key)
            # system_user_add.private_key = private_key
            # system_user_add.public_key = public_key
            system_user_add.auto_push = False
            system_user_add.date_created = timezone.now()
            system_user_add.username = role
            system_user_add.save()
            # logger.info("ip:%s, public_key:%s, private_key:%s\n" %(ip, private_key, public_key))
        except Exception as e:
            logger.info("K8S: SystemUser: name:%s,username:%s error" % (system_user_name, system_user_username))
            return HttpResponse(json.dumps(dict()), content_type="application/json",
                                status=500, reason="Unknown error: %s" % e)
        logger.info("K8S: SystemUser: name:%s,username:%s added!" % (system_user_name, system_user_username))

        # resp = resp + ("public_key:\n%s \nprivate_key:\n%s\n" % (system_user_add.public_key,
        #                            system_user_add.private_key))
        # add admin user
        # ToDo: gen the particular keys
        if int(is_public) == 1:
            admin_user_name = (settings.CONFIG.NAME_FLAG or '') + '_' + (
            settings.CONFIG.PUBLIC_ADMINI_USER_NAME or 'public')
            admin_user_username = settings.CONFIG.PUBLIC_ADMINI_USERNAME or 'root'
            admin_user_password = settings.CONFIG.PUBLIC_ADMINI_USER_PWD or "123456"
        else:
            admin_user_name = (settings.CONFIG.NAME_FLAG) or '' + '_' + (
            settings.CONFIG.BUILD_ADMINI_USER_NAME or 'build')
            admin_user_username = settings.CONFIG.BUILD_ADMINI_USERNAME or 'root'
            admin_user_password = settings.CONFIG.BUILD_ADMINI_USER_PWD or "123456"
        #admin_user_pkey = settings.CONFIG.SYSTEM_USER_PKEY or ''''''
        # admin_user_name = settings.CONFIG.ADMINI_USER_NAME or 'root'
        # admin_user_username = settings.CONFIG.ADMINI_USER_NAME or 'root'
        # admin_user_password = settings.CONFIG.ADMINI_USER_PWD or "123456"
        admin_user_tuple = AdminUser.objects.filter(name=admin_user_name)
        if len(admin_user_tuple) == 1:
            admin_user_add = admin_user_tuple[0]
        else:
            admin_user_tuple.delete()
            admin_user_add = AdminUser.objects.create(name=admin_user_name)
        admin_user_add.username = admin_user_username
        # admin_user_add.password = admin_user_password
        # admin_public_key = ssh_pubkey_gen(private_key=admin_user_pkey, password=admin_user_password)
        admin_user_pkey, admin_public_key = ssh_key_gen(username=system_user_name, password=admin_user_password)
        admin_user_add.set_auth(password=admin_user_password, private_key=admin_user_pkey, public_key=admin_public_key)
        # admin_user_add.private_key = admin_user_pkey
        # ssh_keys = gen_keys() #gen_keys(admin_user_private_key)
        # admin_user_add.private_key = ssh_keys.get('private_key', "private_key wrong")
        # admin_user_add.public_key = ssh_keys.get('public_key', 'public_key wrong')
        admin_user_add.save()
        # logger.info("K8S: AdminUser: name:%s,username:%s added!" % (admin_user_name, admin_user_username))

        # add asset
        # ToDo: judge ip is valid?
        try:
            if checkip(ip):
                asset_ip = ip
                asset_port = settings.CONFIG.IP_PORT or 22
                asset_hostname = '_'.join([asset_ip, str(asset_port)])
                asset_tuple = Asset.objects.filter(hostname=asset_hostname, ip=asset_ip, port=asset_port)
                if len(asset_tuple) == 1:
                    asset_add = asset_tuple[0]
                elif len(asset_tuple) == 0:
                    Asset.objects.filter(hostname=asset_hostname).delete()
                    Asset.objects.filter(ip=asset_ip, port=asset_port).delete()
                    asset_add = Asset.objects.create(hostname=asset_hostname,
                                                     ip=ip, port=asset_port)
                else:
                    asset_tuple.delete()
                    asset_add = Asset.objects.create(hostname=asset_hostname,
                                                     ip=ip, port=asset_port)
                asset_add.admin_user = admin_user_add
                asset_add.save()
                # logger.info("ip:%s, public_key:%s, private_key:%s \n" % (ip, admin_public_key, admin_user_pkey))
                # resp = resp + ("hostname:%s \n" % asset_add.hostname)
                # logger.info("K8S: asset:hostname:%s,ip:%s,port:%s added!" % (asset_hostname, asset_ip, asset_port))
            else:
                return HttpResponse(json.dumps(dict()), content_type="application/json", reason="ip: %s invalid!" % ip,
                                    status=500)
        except Exception as e:
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason="Unknown error: %s" % e,
                                status=500)
        ## 注册密钥
        try:
            logger.info("2211K8S: k8s_exec_command :")
            k8s_passwd = prpcrypt().decrypt(k8s_passwd)
            admin_public_key = public_key
            if role == 'root':
                exec_command = [
                    '/bin/bash',
                    '-c',
                    ROOT_CMD.format(
                        admin_public_key, system_user_name)]
            else:
                exec_command = [
                    '/bin/bash',
                    '-c',
                    ADMIN_CMD.format(
                        admin_public_key, role, system_user_name)]
            logger.info("1111K8S: k8s_exec_command : %s" % exec_command)
            status, reason = k8s_exec_command(k8s_api, k8s_username, k8s_passwd, namespace, pod_name, exec_command)
            # logger.info("K8S: k8s_exec_command: reason: %s" % reason)
            if status == 500 or status == 404:
                logger.info("K8S: k8s_error: %s" % reason)
                return HttpResponse(json.dumps(dict()), content_type="application/json", reason=reason,
                                    status=status)
            # system_user_tuple = SystemUser.objects.filter(name=system_user_name)
            # system_user_add = system_user_tuple[0]
            # system_user_add.username = role
            # system_user_add.save()
        except Exception as e:
            logger.info("K8S: k8s_exec_command: Exception:%s" % e)
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason=e,
                                status=500)

        # 验证登陆
        # import paramiko
        ssh_hello = paramiko.SSHClient()
        try:
            # logger.info("ip: %s, private_key: %s\n" % (asset_add.ip, private_key))
            if private_key and private_key.find('PRIVATE KEY'):
                private_key_rsa = PKey.from_string(private_key)
                key_str = str(private_key_rsa)
                # logger.info("K8S: **private_key_rsa:%r " % key_str )
            else:
                private_key_rsa = None
            ssh_hello.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_hello.connect(hostname=asset_add.ip,
                              port=asset_add.port,
                              username=system_user_add.username,
                              pkey=private_key_rsa,
                              look_for_keys=False,
                              allow_agent=True,
                              timeout=10)
            ssh_hello.close()
        except (paramiko.AuthenticationException,
                paramiko.ssh_exception.SSHException):
            msg = 'Connect backend server %s failed: %s' \
                  % (asset_add.ip, 'Auth failed')
            ssh_hello.close()
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason=msg,
                                status=500)
        except Exception as e:
            ssh_hello.close()
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason=e,
                                status=500)
        # Add perms
        perm_name = '_'.join([user_add.username, asset_add.hostname])
        perm_tuple = AssetPermission.objects.filter(name=perm_name)
        if len(perm_tuple) == 1:
            perm_add = perm_tuple[0]
        else:
            perm_tuple.delete()
            perm_add = AssetPermission.objects.create(name=perm_name)

        if user_add not in perm_add.user_groups.all():
            perm_add.users.add(user_add)
        if asset_add not in perm_add.assets.all():
            perm_add.assets.add(asset_add)
        perm_add.system_users.clear()
        perm_add.system_users.add(system_user_add)
        # from common.utils import date_expired_default
        # perm_add.date_expired = date_expired_default()

        perm_expired = timezone.now() + timezone.timedelta(days=int(days))
        perm_add.date_expired = perm_expired
        perm_add.save()

        logger.info("K8S: perms: name:%s,asset:%s,system_user:%s added!" % (
        perm_add.name, asset_add.hostname, system_user_add.name))
        resp = dict()
        resp['username'] = user_add.username
        resp['password'] = cur_password
        resp['url'] = 'ssh -p%s %s@%s' % (
        settings.CONFIG.COCO_PORT or '2222', erp, settings.CONFIG.COCO_URL or '{coco}')
        # print('end')
        return HttpResponse(json.dumps(resp), content_type="application/json")


@csrf_exempt
def master_auth(request):
    try:
        if not authentication.PrivateTokenAuthentication().authenticate(request):
            return HttpResponse("%s Authentication failed" % request.user, status=401, content_type="application/json")
    except Exception as e:
        return HttpResponse(reason="Unknown error: %s" % e, status=500, content_type="application/json")


    if request.method == 'POST':
        try:
            req = json.loads(request.body)
            logger.info("K8S request body: %s" % req)
            erp = req.get('erp')
            ip = req['ip'].rstrip().lstrip()
            days = req.get('days', 1)
            user_password = req.get('passwd')  # req.get('passwd', GenPassword(16))
            role = req.get('role', 'admin')
        except Exception as e:
            logger.warning("K8S: request post body is null! ip: %s" % ip)
            return HttpResponse(json.dumps(dict()), reason="Unknown error: %s" % e, status=500,
                                content_type="application/json")

        # terminate_connection(d)
        # queryset = ProxyLog.objects.filter(user=erp, terminal='coco', is_finished=False)
        # for proxy_log in queryset:
        #     terminate_connection(proxy_log)
        #     logger.info("K8S: %s is terminated!" % str(proxy_log.id))
        # add user
        user_username = erp
        user_name = erp
        # user_password = GenPassword(15)
        user_email = erp + '@local'
        system_user_name = erp + '_' + ip
        try:
            userList = User.objects.filter(username=user_username, email=user_email)
            if len(userList) == 1:
                user_add = userList[0]
            elif len(userList) == 0:
                User.objects.filter(username=user_username).delete()
                User.objects.filter(email=user_email).delete()
                user_add = User.objects.create(username=user_username, email=user_email)
            else:
                userList.delete()
                user_add = User.objects.create(username=user_username, email=user_email)
            user_add.name = user_name
            cur_password = user_password
            user_add.set_password(cur_password)
            user_add.created_by = erp
            try:
                years = int(settings.CONFIG.USER_EXPIRED_YEARS)
            except TypeError:
                years = 70
            user_expired = timezone.now() + timezone.timedelta(days=365 * years)
            user_add.date_expired = user_expired
            user_add.save()
        except Exception as e:
            return HttpResponse(json.dumps(dict()), content_type="application/json",
                                reason="Unknown error: %s" % e, status=500)
        logger.info("K8S: user: username:%s,pw:%s added!" % (user_username, cur_password))

        # add system user
        try:
            system_user_name = erp + '_' + ip
            system_user_username = role
            private_key, public_key = ssh_key_gen(username=system_user_name)
            system_user_tuple = SystemUser.objects.filter(name=system_user_name)
            if len(system_user_tuple) == 1:
                system_user_add = system_user_tuple[0]
            else:
                system_user_tuple.delete()
                system_user_add = SystemUser.objects.create(name=system_user_name)
            system_user_add.username = system_user_username
            # system_user_add.password = system_user_password
            # system_user_add.AUTH_METHOD_CHOICES = "K"
            system_user_add.set_auth(password='', private_key=private_key, public_key=public_key)
            # system_user_add.private_key = private_key
            # system_user_add.public_key = public_key
            system_user_add.auto_push = False
            system_user_add.date_created = timezone.now()
            system_user_add.username = role
            system_user_add.save()
            # logger.info("ip:%s, public_key:%s, private_key:%s\n" %(ip, private_key, public_key))
        except Exception as e:
            logger.info("K8S: SystemUser: name:%s,username:%s error" % (system_user_name, system_user_username))
            return HttpResponse(json.dumps(dict()), content_type="application/json",
                                status=500, reason="Unknown error: %s" % e)
        logger.info("K8S: SystemUser: name:%s,username:%s added!" % (system_user_name, system_user_username))

        # add admin user

        admin_user_name = (settings.CONFIG.NAME_FLAG) or '' + '_' + (
                settings.CONFIG.BUILD_ADMINI_USER_NAME or 'build')
        admin_user_username = settings.CONFIG.BUILD_ADMINI_USERNAME or 'root'
        admin_user_password = settings.CONFIG.BUILD_ADMINI_USER_PWD or "123456"
        # admin_user_pkey = settings.CONFIG.SYSTEM_USER_PKEY or ''''''
        # admin_user_name = settings.CONFIG.ADMINI_USER_NAME or 'root'
        # admin_user_username = settings.CONFIG.ADMINI_USER_NAME or 'root'
        # admin_user_password = settings.CONFIG.ADMINI_USER_PWD or "123456"
        admin_user_tuple = AdminUser.objects.filter(name=admin_user_name)
        if len(admin_user_tuple) == 1:
            admin_user_add = admin_user_tuple[0]
        else:
            admin_user_tuple.delete()
            admin_user_add = AdminUser.objects.create(name=admin_user_name)
        admin_user_add.username = admin_user_username
        # admin_user_add.password = admin_user_password
        # admin_public_key = ssh_pubkey_gen(private_key=admin_user_pkey, password=admin_user_password)
        admin_user_pkey, admin_public_key = ssh_key_gen(username=system_user_name, password=admin_user_password)
        admin_user_add.set_auth(password=admin_user_password, private_key=admin_user_pkey, public_key=admin_public_key)
        # admin_user_add.private_key = admin_user_pkey
        # ssh_keys = gen_keys() #gen_keys(admin_user_private_key)
        # admin_user_add.private_key = ssh_keys.get('private_key', "private_key wrong")
        # admin_user_add.public_key = ssh_keys.get('public_key', 'public_key wrong')
        admin_user_add.save()

        logger.info("K8S: AdminUser: name:%s,username:%s added!" % (admin_user_name, admin_user_username))

        # add asset
        # ToDo: judge ip is valid?
        try:
            if checkip(ip):
                asset_ip = ip
                asset_port = settings.CONFIG.IP_PORT or 22
                asset_hostname = '_'.join([asset_ip, str(asset_port)])
                asset_tuple = Asset.objects.filter(hostname=asset_hostname, ip=asset_ip, port=asset_port)
                if len(asset_tuple) == 1:
                    asset_add = asset_tuple[0]
                elif len(asset_tuple) == 0:
                    Asset.objects.filter(hostname=asset_hostname).delete()
                    Asset.objects.filter(ip=asset_ip, port=asset_port).delete()
                    asset_add = Asset.objects.create(hostname=asset_hostname,
                                                     ip=ip, port=asset_port)
                else:
                    asset_tuple.delete()
                    asset_add = Asset.objects.create(hostname=asset_hostname,
                                                     ip=ip, port=asset_port)
                asset_add.admin_user = admin_user_add
                asset_add.save()
                #resp = resp + ("hostname:%s \n" % asset_add.hostname)
        except Exception as e:
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason="Unknown error: %s" % e,
                                    status=500)

        logger.info("K8S: asset:hostname:%s,ip:%s,port:%s added!" % (asset_hostname, asset_ip, asset_port))
        # 使用密码登陆
        success_flag = 0
        for password_auth in [r"nBrO7ssgRo&%Q^OQ~WAa-5;s", r"l#YdRqZ8GlpKfZ5r4EFklVpO5x*R2",
                              r"g7%zhije2iIx@i67DcyUf", r"D#<K.4mZU-1Wc#M6Jnr*vPuN"]:
            logger.info("%s,%s,%s,%s" % (asset_add.ip, asset_add.port, password_auth, "root"))
            try:
                ssh_hello = paramiko.SSHClient()
                ssh_hello.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # ssh.connect(hostname=ip, port=22, username='root', password=password)
                ssh_hello.connect(hostname=asset_add.ip, port=asset_add.port,
                                  username="root",
                                  password=password_auth,
                                  look_for_keys=False, allow_agent=True,
                                  compress=True, timeout=100)
                # Push system user
                logger.info('Push system user %s' % system_user_add.name)
                system_user_add.username = "root"
                system_user_add.set_auth(password=password_auth, private_key="", public_key="")
                system_user_add.auto_push = False
                system_user_add.date_created = timezone.now()
                system_user_add.username = role
                system_user_add.save()
                break
            except (paramiko.AuthenticationException, paramiko.ssh_exception.SSHException):
                msg = 'Connect backend server %s failed: %s' \
                      % (asset_add.ip, 'Auth failed')
                logger.info(msg)
                continue
        if (success_flag == 0):
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason="error: passwd is error",
                                status=500)

     # 使用密钥登陆
#         for id_rsa in [r"""-----BEGIN RSA PRIVATE KEY-----
# MIIEowIBAAKCAQEA3td5r+NyzEHnjqPzz01UdSdaFhP5cr3VjCx9f6KCSqfSEDdk
# D1v/EnqcSvOj4Vs+HHL5Xo9HpSbo1pTeRxV0JZBe47lCwNwIjNiOi26AZZ9GwJS8
# hfl0XCtHWgXVdys+yQvIK7N642ckMjRFHxNkS4pjvemxvLMxvicAricAmZgEsENA
# lBvtFd7V4DdHuKLd3tAopQfbFMrVtKHewUl+XzULrPjfsXxIpODYon9jjcvJRYFR
# hIa/MjouK7JiroSRP72OzeB7sC6xzHQLld7HeSzRWdRhGACxwz5M9wawIRRh2vCT
# n7q5i5eDkyinx1TQGsjOrB4UUyV66ZHtVjF2UQIBIwKCAQEAknBXR7K5JyP+kO9l
# tBzfurN1tryrPMXkGkkfRT7n5+qf/Ackfx8ylx1fZHQ4fiYEPpSyf/fBXeZefmHT
# 5ZHBWoNxjlUr3dJsBMjSs2XfWLkf3aOR1GIZQ+HtD0WpiNNGhB2vbSzNGRfklgUX
# etI6mAp8DxXp08Y2oYdYN+2+kNBiv4umwKcolRC/vVfg6cWlVmLVfVQ6Fs/cE4mX
# OsgeimF7gUSEAFcq08LntAzdB6vkvkEft0dDcY5pcspgQNNILBw27vF8hsqLqkpY
# JCeCnvEiqjWqx46BZtyO1cjI2Lw63+1g/tb8PfC4/hEauF4Dqi+lxK1g/Wk98rJc
# jwpFXwKBgQDxm6IXONPLkF+kGn1X18jEfVVip8G1FS57kk8HF8KXmp2TxeVBOpmg
# C9gOI/rf2vRWBFBQyKBOWAIHvzlc4kdMEdLMQfagf     JDi4minc2H8oi7W+QIHydKD
# hhXju5vEg2GopW/eiWb4vaXoOg33J95k1Djdv699sThga/jMGEJD5wKBgQDsHatB
# 3RIbawGIbfFtGPAdx8L7jHgQYnZOBJe54MWtKaoVAPlE5avs/b7OE3wR9RSn3OQp
# g5tjQ61Zb+DioT6JcFummr0o1c3CumKbOWIPMwl3ttm5mPEmil5YOOBVzlGBAiKb
# 65Iqsngoy1m0e8X2ZPmFXPdyV/Povl0wN74tBwKBgQDqtHGS5r8dhO8xs1Uwwv2L
# rPPcLe9fc6l/Wu2vHmVC0LZVCWJcn1NoRgUVDQJVzWJiMBOBrPN/Ti3bo9FS6nEl
# UySL6E6qh6KwhCsmUtQ3Pnak8eS3G9PQORyUFVV9EenXBxw3Q6XbsOpPTla1lHGj
# xtgn3se77fxAaOMPaAXbjwKBgQCbKXCKXhM2lsZ+OZ6mxz60e/Uo9eh/y6zULudc
# 5CohVeTL+VNZKTZ3KmdxeoS7V+kAmHitkP+2QmqZ285LyQvWqOvFQR04F3iV6DIr
# fXr0C5iB3o8TkGP0wVPw1OsxEo1UxuOLCISftxvDCUmT3E7jvrKZd5tLI9rMJVMu
# UIRJeQKBgGwA0IIwGm988+m9McD76fCitatvDY3rdBDV5Uu/FgYqKSyhIuctsOWW
# PrfJZnPaWClOWjBcgj0udD9NyLlN48MSt97OMJ6hRhkQjVxLy4b67B9xa59AbGpo
# tYSq0G5iXDdB2pjZ/65p8oQHjiOiK70/gypS5wSIVYHOSp0e0egU
# -----END RSA PRIVATE KEY-----"""]:
#             logger.info("%s,%s,%s,%s" % (asset_add.ip, asset_add.port, id_rsa, "root"))
#             try:
#                 private_key_rsa = PKey.from_string(private_key)
#                 ssh_hello = paramiko.SSHClient()
#                 ssh_hello.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#                 # ssh.connect(hostname=ip, port=22, username='root', password=password)
#
#                 ssh_hello.connect(hostname=asset_add.ip, port=asset_add.port,
#                                   username="root",
#                                   pkey=private_key_rsa,
#                                   allow_agent=True,
#                                   timeout=100)
#                 # Push system user
#                 logger.info('Push system user %s' % system_user_add.name)
#                 system_user_add.username = "root"
#                 system_user_add.set_auth(password="", private_key=private_key_rsa, public_key="")
#                 system_user_add.auto_push = False
#                 system_user_add.date_created = timezone.now()
#                 system_user_add.username = role
#                 system_user_add.save()
#                 break
#             except (paramiko.AuthenticationException, paramiko.ssh_exception.SSHException):
#                 msg = 'Connect backend server %s failed: %s' \
#                       % (asset_add.ip, 'Auth failed')
#                 logger.info(msg)
#                 continue

        # Add perms
        perm_name = '_'.join([user_add.username, asset_add.hostname])
        perm_tuple = AssetPermission.objects.filter(name=perm_name)
        if len(perm_tuple) == 1:
            perm_add = perm_tuple[0]
        else:
            perm_tuple.delete()
            perm_add = AssetPermission.objects.create(name=perm_name)

        if user_add not in perm_add.user_groups.all():
            perm_add.users.add(user_add)
        if asset_add not in perm_add.assets.all():
            perm_add.assets.add(asset_add)
        if system_user_add not in perm_add.system_users.all():
            perm_add.system_users.add(system_user_add)

        perm_expired = timezone.now() + timezone.timedelta(days=int(days))
        perm_add.date_expired = perm_expired
        perm_add.save()
        logger.info("K8S: perms: name:%s,asset:%s,system_user:%s added!" %(perm_add.name, asset_add.hostname, system_user_add.name))

        resp = dict()
        resp['username'] = user_add.username
        resp['password'] = cur_password
        resp['url'] = 'ssh -p%s %s@%s' % (settings.CONFIG.COCO_PORT or '2222', erp, settings.CONFIG.COCO_URL or '{coco}')
        print('end')
        return HttpResponse(json.dumps(resp), content_type="application/json")

@csrf_exempt
def erp_binding_ips(request):
    try:
        # from users import authentication
        if not authentication.PrivateTokenAuthentication().authenticate(request):
            return HttpResponse("%s Authentication failed" % request.user, status=401, content_type="application/json")
    except Exception as e:
        return HttpResponse(reason="Unknown error: %s" % e, status=500, content_type="application/json")

    if request.method == 'POST':
        try:
            req = json.loads(request.body)
            erp = req['erp']
            # ip = req.get('ip')
            is_public = req.get('is_public', 0)
            user_password = req.get('passwd', GenPassword(16))
            logger.info("K8S: erp: %s" % erp)
            # k8s parametes
            k8s_api = req['K8sAPI']
            # namespace = req.get('system')
            # pod_name = req.get('podName')
            k8s_username = req["K8sUserName"]
            k8s_passwd = req["K8sPassword"]
            # other parametes
            days = req.get('days', 1)
            role = req.get('role', 'admin')
            # auth_mode = req.get('auth_mode', "kube")
            ips = req['ips']
        except Exception as e:
            logger.warning("K8S: request post body is null!")
            return HttpResponse(reason="Unknown error: %s" % e, status=500, content_type="application/json")

        # terminate_connection(d)
        # queryset = ProxyLog.objects.filter(user=erp, terminal='coco', is_finished=False)
        # for proxy_log in queryset:
        #     terminate_connection(proxy_log)
        #     logger.info("K8S: %s is terminated!" % str(proxy_log.id))
        # add user
        user_username = erp
        user_name = erp
        # user_password = GenPassword(15)
        user_email = erp + '@local'
        try:
            userList = User.objects.filter(username=user_username, email=user_email)
            if len(userList) == 1:
                user_add = userList[0]
            elif len(userList) == 0:
                User.objects.filter(username=user_username).delete()
                User.objects.filter(email=user_email).delete()
                user_add = User.objects.create(username=user_username, email=user_email)
            else:
                userList.delete()
                user_add = User.objects.create(username=user_username, email=user_email)
            user_add.name = user_name
            cur_password = user_password
            user_add.set_password(cur_password)
            user_add.created_by = request.user
            # try:
            #     years = int(settings.CONFIG.USER_EXPIRED_YEARS)
            # except TypeError:
            #     years = 70
            # user_expired = timezone.now() + timezone.timedelta(days=365 * years)
            # user_add.date_expired = user_expired
            user_add.save()
        except Exception as e:
            return HttpResponse(json.dumps(dict()), content_type="application/json", reason="Unknown error: %s" % e,
                                status=500)
        logger.info("K8S: user: username:%s,email:%s added!" % (user_username, user_email))
        # add system user
        from django.db.utils import IntegrityError
        try:
            for item in ips:
                ip = item.get('ip')
                namespace = item.get("system")
                pod_name = item.get("podName")
                # add system_user
                system_user_name = erp + '_' + ip
                if int(is_public) == 1:
                    # system_user_name = settings.CONFIG.PUBLIC_SYSTEM_USER_NAME or 'public'
                    system_user_username = settings.CONFIG.PUBLIC_SYSTEM_USERNAME or 'admin'
                    # system_user_password = settings.CONFIG.PUBLIC_SYSTEM_USER_PWD or '123456'
                else:
                    # system_user_name = settings.CONFIG.BUILD_SYSTEM_USER_NAME or 'build'
                    system_user_username = settings.CONFIG.BUILD_SYSTEM_USERNAME or 'admin'
                    # system_user_password = settings.CONFIG.BUILD_SYSTEM_USER_PWD or '123456'
                # system_user_name = settings.CONFIG.SYSTEM_USER_NAME or 'admin'
                # system_user_username = settings.CONFIG.SYSTEM_USER_NAME or 'admin'
                # system_user_password = settings.CONFIG.SYSTEM_USER_PWD or '123456'
                private_key, public_key = ssh_key_gen(username=system_user_name)
                system_user_tuple = SystemUser.objects.filter(name=system_user_name)
                if len(system_user_tuple) == 1:
                    system_user_add = system_user_tuple[0]
                else:
                    system_user_tuple.delete()
                    system_user_add = SystemUser.objects.create(name=system_user_name)
                system_user_add.username = system_user_username
                # system_user_add.password = system_user_password
                system_user_add.AUTH_METHOD_CHOICES = "K"
                system_user_add.private_key = private_key
                system_user_add.public_key = public_key
                system_user_add.auto_push = False
                system_user_add.save()
                logger.info("K8S: SystemUser: name:%s,username:%s added!" % (system_user_name, system_user_username))
                # add admin user
                # ToDo: gen the particular keys
                if int(is_public) == 1:
                    admin_user_name = (settings.CONFIG.NAME_FLAG or '') + '_' + (
                        settings.CONFIG.PUBLIC_ADMINI_USER_NAME or 'public')
                    admin_user_username = settings.CONFIG.PUBLIC_ADMINI_USERNAME or 'root'
                    admin_user_password = settings.CONFIG.PUBLIC_ADMINI_USER_PWD or "123456"
                else:
                    admin_user_name = (settings.CONFIG.NAME_FLAG) or '' + '_' + (
                        settings.CONFIG.BUILD_ADMINI_USER_NAME or 'build')
                    admin_user_username = settings.CONFIG.BUILD_ADMINI_USERNAME or 'root'
                    admin_user_password = settings.CONFIG.BUILD_ADMINI_USER_PWD or "123456"
                admin_user_pkey = settings.CONFIG.SYSTEM_USER_PKEY or ''''''
                admin_user_tuple = AdminUser.objects.filter(name=admin_user_name)
                if len(admin_user_tuple) == 1:
                    admin_user_add = admin_user_tuple[0]
                else:
                    admin_user_tuple.delete()
                    admin_user_add = AdminUser.objects.create(name=admin_user_name)
                admin_user_add.username = admin_user_username
                admin_user_add.password = admin_user_password
                admin_user_add.private_key = admin_user_pkey
                admin_user_add.save()
                logger.info("K8S: AdminUser: name:%s,username:%s added!" % (admin_user_name, admin_user_username))
                # add assets
                if checkip(ip):
                    asset_ip = ip
                    asset_port = settings.CONFIG.IP_PORT or 22
                    asset_hostname = '_'.join([asset_ip, str(asset_port)])
                    asset_tuple = Asset.objects.filter(hostname=asset_hostname, ip=asset_ip, port=asset_port)
                    if len(asset_tuple) == 1:
                        asset_add = asset_tuple[0]
                    elif len(asset_tuple) == 0:
                        Asset.objects.filter(hostname=asset_hostname).delete()
                        Asset.objects.filter(ip=asset_ip, port=asset_port).delete()
                        asset_add = Asset.objects.create(hostname=asset_hostname,
                                                         ip=ip, port=asset_port)
                    else:
                        asset_tuple.delete()
                        asset_add = Asset.objects.create(hostname=asset_hostname,
                                                         ip=ip, port=asset_port)
                    asset_add.admin_user = admin_user_add
                    asset_add.save()
                    # resp = resp + ("hostname:%s \n" % asset_add.hostname)
                    logger.info("K8S: asset:hostname:%s,ip:%s,port:%s added!" % (asset_hostname, asset_ip, asset_port))
                else:
                    return HttpResponse(json.dumps(dict()), content_type="application/json",
                                        status=500, reason="ip wrong: %s" % ip)
                # 使用k8s接口动态注入密钥
                k8s_passwd_d = prpcrypt().decrypt(k8s_passwd)
                admin_public_key = public_key
                if role == 'root':
                    exec_command = [
                        '/bin/sh',
                        '-c',
                        ROOT_CMD.format(
                            public_key_string, system_user_name)]
                else:
                    exec_command = [
                        '/bin/sh',
                        '-c',
                        ADMIN_CMD.format(
                            admin_public_key, role, system_user_name)]
                status, reason = k8s_exec_command(k8s_api, k8s_username, k8s_passwd_d, namespace, pod_name,
                                                  exec_command)
                if status == 500 or status == 404:
                    return HttpResponse(json.dumps(dict()), content_type="application/json", reason=reason,
                                        status=status)
                system_user_add.username = role
                system_user_add.save()
                # Add perms
                perm_name = '_'.join([user_add.username, asset_add.hostname])
                perm_tuple = AssetPermission.objects.filter(name=perm_name)
                if len(perm_tuple) == 1:
                    perm_add = perm_tuple[0]
                else:
                    perm_tuple.delete()
                    perm_add = AssetPermission.objects.create(name=perm_name)

                if user_add not in perm_add.user_groups.all():
                    perm_add.users.add(user_add)
                if asset_add not in perm_add.assets.all():
                    perm_add.assets.add(asset_add)
                perm_add.system_users.clear()
                perm_add.system_users.add(system_user_add)
                # from common.utils import date_expired_default
                # perm_add.date_expired = date_expired_default()
                perm_expired = timezone.now() + timezone.timedelta(days=int(days))
                perm_add.date_expired = perm_expired
                perm_add.save()
                logger.info("K8S: perms: name:%s,asset:%s,system_user:%s added!" % (
                    perm_add.name, asset_add.hostname, system_user_add.name))
        except Exception as e:
            return HttpResponse(json.dumps(dict()), content_type="application/json",
                                status=500, reason="Unknown error: %s" % e)
        resp = dict()
        resp['username'] = user_add.username
        resp['password'] = cur_password
        resp['url'] = 'ssh -p%s %s@%s' % (
        settings.CONFIG.COCO_PORT or '2222', erp, settings.CONFIG.COCO_URL or '{coco}')
        print('end')
        return HttpResponse(json.dumps(resp), content_type="application/json")


@csrf_exempt
def erp_binding_ad(request):
    pass


def query(request, erp):
    try:
        k8s_user = User.objects.get(username=erp)
    except Exception as e:
        return HttpResponse(str(e))
    resp = dict()
    resp['username'] = k8s_user.username
    resp['password'] = k8s_user.password
    resp['url'] = settings.CONFIG.JUMPSERVER_URL or 'localhost'
    return HttpResponse(json.dumps(resp), content_type="application/json")



