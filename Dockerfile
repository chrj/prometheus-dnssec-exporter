FROM scratch
LABEL maintainer="Harald Koch <harald.koch@gmail.com>"

COPY prometheus-dnssec-exporter /bin/prometheus-dnssec-exporter
COPY config.sample /etc/dnssec-checks

EXPOSE      9204
ENTRYPOINT  [ "/bin/prometheus-dnssec-exporter" ]
