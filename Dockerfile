FROM docker.io/golang:1.14.15-alpine as builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG VERSION

ENV CGO_ENABLED=0 \
    GOPATH=/go \
    GOBIN=/go/bin \
    GO111MODULE=on

WORKDIR /workspace

COPY . .

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN \
  export GOOS \
  && GOOS=$(echo ${TARGETPLATFORM} | cut -d / -f1) \
  && export GOARCH \
  && GOARCH=$(echo ${TARGETPLATFORM} | cut -d / -f2) \
  && export GOARM \
  && GOARM=$(echo ${TARGETPLATFORM} | cut -d / -f3 | cut -c2-) \
  && go build -o /bin/prometheus-dnssec-exporter -ldflags="-w -s"


FROM quay.io/prometheus/busybox:glibc

COPY --from=builder /bin/prometheus-dnssec-exporter /bin/prometheus-dnssec-exporter
COPY config.sample /etc/dnssec-checks

EXPOSE      9204
USER        nobody
ENTRYPOINT  [ "/bin/prometheus-dnssec-exporter" ]

LABEL maintainer="Harald Koch <harald.koch@gmail.com>"
