FROM alpine:3.24.1

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
