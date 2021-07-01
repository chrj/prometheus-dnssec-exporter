ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:glibc
LABEL maintainer="Harald Koch <harald.koch@gmail.com>"

COPY prometheus-dnssec-exporter /bin/prometheus-dnssec-exporter
COPY config.sample /etc/dnssec-checks

EXPOSE      9204
USER        nobody
ENTRYPOINT  [ "/bin/prometheus-dnssec-exporter" ]
