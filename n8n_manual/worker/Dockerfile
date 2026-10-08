# Primera etapa: compilar las herramientas
ARG GO_IMAGE=golang:latest
FROM ${GO_IMAGE} AS tools

ENV CGO_ENABLED=0

ARG SUBFINDER_VERSION=latest
ARG HTTPX_VERSION=latest

RUN GOBIN=/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

RUN GOBIN=/out go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}


# Segunda etapa: preparar la imagen del trabajador
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/sh ti1 \
    && mkdir -p /run/sshd /opt/recon /home/ti1/evidence \
    && chown ti1:ti1 /home/ti1/evidence

COPY --from=tools /out/subfinder /usr/local/bin/subfinder
COPY --from=tools /out/httpx /usr/local/bin/httpx

COPY recon.py /opt/recon/recon.py
COPY start.sh /usr/local/bin/start-worker

RUN chmod 755 /usr/local/bin/start-worker

CMD ["/usr/local/bin/start-worker"]