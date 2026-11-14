# rvs: shells through Pasarguard reverse-tunnel devices. See compose.yaml for how to run it.
#
#   docker build -t rvs .
ARG PYTHON_VERSION=3.14
# Linux tun autoSystemRoutingTable needs Xray >= 26.6.27 (XTLS/Xray-core#6366).
ARG XRAY_VERSION=26.11.9

# Upstream image is distroless (xray only), so take just the static binary from it.
FROM ghcr.io/xtls/xray-core:${XRAY_VERSION} AS xray

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY pyproject.toml /build/rvs/pyproject.toml
COPY src /build/rvs/src
RUN pip install --no-cache-dir /build/rvs grpcio-tools
# Add GetUsersOnlineIpListStats to the installed bridge, as the panel image does (proto/ and scripts/
# are copies from the panel repo; see README).
COPY proto/service.proto /build/proto/service.proto
COPY scripts/regenerate_node_bridge_proto.py /build/scripts/regenerate_node_bridge_proto.py
# grpcio-tools (and the grpcio/setuptools it pulls in) is only for the regen; the bridge uses grpclib.
# The import check makes a bridge/proto mismatch fail the build, not the first run.
RUN python /build/scripts/regenerate_node_bridge_proto.py \
    && pip uninstall -y grpcio-tools grpcio setuptools && pip check \
    && python -c "import PasarGuardNodeBridge, pasarguard_rvs.cli; from PasarGuardNodeBridge.common.service_pb2 import StatsAllOnlineIpListResponse"

FROM python:${PYTHON_VERSION}-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 curl dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
ENTRYPOINT ["rvs"]
CMD ["shell"]
