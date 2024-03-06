#!/bin/bash

image=grom-admin:$1
name=grom-admin
#docker pull $image
docker rm -f $name
docker run -d --restart=always  --name=$name\
    -v /home/wilson/workspace/grom/grom-admin/app.conf:/opt/grom-admin/app.conf \
    -v /home/wilson/workspace/grom/grom-admin/src:/opt/grom-admin/src \
    -p 10001:10001 \
    $image 
