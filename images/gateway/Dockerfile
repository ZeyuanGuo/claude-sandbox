ARG BASE_IMAGE=docker.io/mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f
FROM ${BASE_IMAGE}

USER root

RUN pip install --no-cache-dir PyYAML==6.0.3

COPY src /opt/cdm/src
COPY gateway/mitmproxy/cdm_addon.py /opt/cdm/gateway/cdm_addon.py
COPY gateway/mitmproxy/entrypoint.sh /opt/cdm/gateway/entrypoint.sh

RUN chmod 0755 /opt/cdm/gateway/entrypoint.sh

ARG GATEWAY_BUILD_DIGEST
LABEL org.controlled-dev-machine.gateway-build-digest=${GATEWAY_BUILD_DIGEST}

ENV PYTHONPATH=/opt/cdm/src

ENTRYPOINT ["/opt/cdm/gateway/entrypoint.sh"]
