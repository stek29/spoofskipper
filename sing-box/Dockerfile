ARG REVISION
FROM ghcr.io/sagernet/sing-box:${REVISION}

RUN set -eu \
    ; apk add --no-cache \
    jsonnet \
    bash \
    ;

COPY ./entrypoint /
ENTRYPOINT [ "/entrypoint" ]
