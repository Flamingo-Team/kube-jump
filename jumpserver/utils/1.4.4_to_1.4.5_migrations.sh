#!/bin/bash
# 

host=172.18.208.48
port=80
username=jumpserver
db=jumpserver

echo "备份原来的 migrations"
mysqldump -u${username} -h${host} -P${port} -p ${db} django_migrations > django_migrations.sql.bak
ret=$?

if [ ${ret} == "0" ];then
    echo "开始使用新的migrations文件"
    mysql -u${username} -h${host} -P${port} -p ${db} < django_migrations.sql
else
    echo "Not valid"
fi


