# generar/reproducir la evidencia.
FROM ubuntu:22.04

RUN apt-get update -qq \
    && apt-get install -y -qq iptables iproute2 procps coreutils sudo openssh-client openssh-server \
    && rm -rf /var/lib/apt/lists/*

COPY invoke-ir.sh /invoke-ir.sh
RUN chmod +x /invoke-ir.sh

ENTRYPOINT ["/invoke-ir.sh"]
