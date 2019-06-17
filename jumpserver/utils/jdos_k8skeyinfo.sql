 CREATE TABLE `K8S_k8skeyinfo` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'id',
  `k8s_api` varchar(128) NOT NULL COMMENT 'k8s_api',
  `k8s_user_name` varchar(128) NOT NULL COMMENT 'k8s_user_name',
  `k8s_passwd` varchar(128) NOT NULL COMMENT 'k8s_passwd',
  `k8s_system` varchar(128) NOT NULL COMMENT 'k8s_system',
  `k8s_pod_name` varchar(128) NOT NULL COMMENT 'k8s_system',
  `assets_system_user` varchar(128) NOT NULL COMMENT 'name',
  `docker_ip` varchar(39) NOT NULL COMMENT 'docker_ip',
  `comment` varchar(10000) DEFAULT NULL COMMENT 'comment',
  `date_created` datetime DEFAULT NULL COMMENT 'date_created',
  `created_by` varchar(100) NOT NULL COMMENT 'created_by',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1DEFAULT CHARSET=utf8 COMMENT='k8s_key_info';