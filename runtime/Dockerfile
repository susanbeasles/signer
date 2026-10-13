# Supply a reviewed base with Node24+, Git, official op, OpenSSH and setpriv
# already installed. This recipe performs no package install or network fetch.
ARG SIGNING_BASE_IMAGE
FROM ${SIGNING_BASE_IMAGE}
ARG SIGNING_BASE_IMAGE
ARG SIGNING_NODE_SHA256
ARG SIGNING_SETPRIV_SHA256
USER root
WORKDIR /opt/signing-control
COPY runtime/ ./runtime/
COPY src/ ./src/
# Public, approved {services,runtime} only. Never supply tokens/private keys.
COPY image-runtime-config.json ./config/runtime.json
RUN ["/usr/bin/node", "/opt/signing-control/runtime/check-image.mjs"]
ENV NODE_EXTRA_CA_CERTS=/etc/cloudflare/certs/cloudflare-containers-ca.crt
EXPOSE 8080
# setpriv execs Node; Node remains PID1. No shell and no credential arguments.
ENTRYPOINT ["/usr/bin/setpriv", "--reuid=10001", "--regid=10001", "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/node", "/opt/signing-control/runtime/container-server.mjs"]
