# IMPORTANT: Any change affecting this image requires manually incrementing
# VERSION_UNBOUND in ../.env so a new image tag is published.
# (REVISION_ALPINE_IMAGE bumps are reflected in the tag automatically.)

ARG BASE_VER
FROM alpine:${BASE_VER}

ARG REVISION
RUN apk add --no-cache \
    "unbound${REVISION:+=$REVISION}" \
    gettext \
    ca-certificates

COPY entrypoint /entrypoint

ENTRYPOINT ["/entrypoint"]
CMD ["-d", "-c", "/tmp/unbound.conf"]

ENV UNBOUND_EXTRA_MODULES=validator \
    UNBOUND_DNS64_PREFIX="64:ff9b::/96" \
    UNBOUND_FORWARD_ADDR="8.8.8.8" \
    UNBOUND_FORWARD_ADDR="8.8.8.8" \
    UNBOUND_FORWARD_TCP="no" \
    UNBOUND_FORWARD_TLS="no" \
    UNBOUND_SRC_CONF="/etc/unbound/unbound.conf" \
    UNBOUND_LISTEN_PORT="53"
