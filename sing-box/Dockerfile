# IMPORTANT: Any change affecting this image requires manually incrementing
# VERSION_SINGBOX in ../.env so a new image tag is published.

ARG REVISION
FROM ghcr.io/sagernet/sing-box:${REVISION}

RUN set -eu \
    ; apk add --no-cache \
    jsonnet \
    bash \
    python3 \
    ;

COPY ./manager/spoofskipper_manager /opt/manager/spoofskipper_manager
COPY ./entrypoint ./reload /
ENTRYPOINT [ "/entrypoint" ]
