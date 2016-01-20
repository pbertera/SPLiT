#!/bin/bash

if [ -z $1 ];then
    version=$(git describe --abbrev=0 --tags)
else
    version=$1
fi

cat << EOF>Dockerfile
FROM alpine:latest

ENV VER ${version}
ENV SPLIT_SRC https://github.com/pbertera/SPLiT/archive/\${VER}.tar.gz

RUN apk update && apk add \
        python bash curl

RUN mkdir /opt && cd /opt && curl -L -k \${SPLIT_SRC} | tar xzvf -
WORKDIR /opt/SPLiT-\${VER}

ADD wrapper.sh /opt/SPLiT-\${VER}/

ENTRYPOINT ["./wrapper.sh"]

EOF
