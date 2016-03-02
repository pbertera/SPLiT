FROM alpine:latest

ENV VER 1.1.3
ENV SPLIT_SRC https://github.com/pbertera/SPLiT/archive/${VER}.tar.gz

RUN apk update && apk add         python bash curl

RUN mkdir /opt && cd /opt && curl -L -k ${SPLIT_SRC} | tar xzvf -
WORKDIR /opt/SPLiT-${VER}

ADD wrapper.sh /opt/SPLiT-${VER}/

ENTRYPOINT ["./wrapper.sh"]

