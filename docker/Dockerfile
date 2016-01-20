FROM alpine:latest

ENV SPLIT_SRC https://github.com/pbertera/SPLiT/archive/1.1.1.tar.gz

RUN apk update && apk add \
	python bash curl

RUN mkdir /opt && cd /opt && curl -L -k ${SPLIT_SRC} | tar xzvf -
WORKDIR /opt/SPLiT-1.1.1

ADD wrapper.sh /opt/SPLiT-1.1.1

ENTRYPOINT ["./wrapper.sh"]
