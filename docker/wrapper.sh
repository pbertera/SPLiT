#!/bin/bash

if [ "$1" == "help" ];then
	echo "If \$LOCAL_IP is defined SPLiT will run with -i \$LOCAL_IP, otherwise will try to find the local ip looking in /etc/hosts"
    exit
fi

if [ -z $LOCAL_IP ];then
	# FIXME: too stupid and error-prone
    LOCAL_IP=$(getent hosts $(hostname)| cut -d \  -f1)
fi

echo LOCAL_IP is ${LOCAL_IP}
echo Executing SPLIT.py $@

exec python ./SPLiT.py -i $LOCAL_IP $@
