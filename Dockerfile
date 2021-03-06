ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:glibc
LABEL maintainer="Stany MARCEL <stanypub@gmail.com>"

ARG ARCH="amd64"
ARG OS="linux"

COPY .build/${OS}-${ARCH}/honeypot_exporter /bin/honeypot_exporter

EXPOSE      9733
ENTRYPOINT  [ "/bin/honeypot_exporter" ]
