# kube-jump
**kubernetes集群堡垒机系统**
--·· SSH登录k8s集群容器之授权管理平台

该系统是在[jumpserver](https://github.com/jumpserver/jumpserver)的基础上调用了k8s的远程接口，实现密钥注入功能，并使用[coco](https://github.com/jumpserver/coco)登录到k8s集群的容器，最终实现了基于k8s的全功能运维堡垒机系统。
该系统包含两部分：kube-jump和kube-coco;

#### [kube-jump](https://github.com/Flamingo-Team/kube-jump.git): 堡垒机管理系统
#### [kube-coco](https://github.com/Flamingo-Team/kube-coco.git): 堡垒机登录终端系统

安装时，根据[jumpserver官方安装指南](http://docs.jumpserver.org/zh/docs/step_by_step.html#jumpserver)安装即可，需要注意的是，在执行**2.7**（修改 Jumpserver 配置文件）之前，到数据库创建一个库，文件在[sql](https://github.com/Flamingo-Team/kube-jump/blob/master/jumpserver/utils/K8S_k8skeyinfo.sql)，创建后，继续执行下面的步骤即可。

运维通过接口给用户授权容器，接口如下：
curl -g -i -X POST  -H 'Content-Type: application/json' -H 'Authorization:Token 4680e4ln63rjfo6duggofs8ndkrq4lp1eg' -d  '{"erp":"zhangsan","role":"root","days":"3","system":"k8s-system","podName":"k8s-pod-name", "ip":"10.182.1.1","passwd":"login-coco-password","K8sAPI":"https://172.168.1.11:443","K8sUserName":"console","K8sPassword":"k8s-cluter-password"}' http://172.168.1.10/api/k8s/v1/apply -v

用户只需要登录coco终端，登录终端后会显示当前用的可以连接的容器，输入序号，直接连接容器即可，非常简单的k8s容器登录管理系统。
运维可以登陆server页面，查看

#### 以下是Jumpserver的相关介绍：

Jumpserver是全球首款完全开源的堡垒机，使用GNU GPL v2.0开源协议，是符合 4A 的专业运维审计系统。

Jumpserver使用Python / Django 进行开发，遵循 Web 2.0 规范，配备了业界领先的 Web Terminal 解决方案，交互界面美观、用户体验好。

Jumpserver采纳分布式架构，支持多机房跨区域部署，中心节点提供 API，各机房部署登录节点，可横向扩展、无并发限制。
