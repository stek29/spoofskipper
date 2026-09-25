# IMPORTANT: Any change affecting this image requires manually incrementing
# VERSION_ZAPRET2 in ../.env so a new image tag is published.
# (REVISION_ALPINE_IMAGE bumps are reflected in the tag automatically.)

ARG BASE_VER

# Downloads only, runs natively on the build platform and fetches files for TARGETARCH.
FROM --platform=$BUILDPLATFORM alpine:${BASE_VER} AS builder

RUN apk add --no-cache \
    curl \
    tar \
    xz \
    ;

ARG TARGETARCH
ARG REVISION
# static curl with HTTP/3 support, for blockcheck2 QUIC tests
ARG CURL_VERSION=8.22.0

# zapret2: extract only needed files and move binaries to where blockcheck2 expects them:
#  - nfqws2 and mdig binaries for target platform
#  - lua desync libraries
#  - binary fake files
#  - blockcheck2 with its dependencies
# TODO: verify archive checksums (sha256sum.txt / SHA256SUMS in the releases)
RUN set -eu \
    ; case "${TARGETARCH}" in \
        amd64) zarch=x86_64 ; carch=x86_64 ;; \
        arm64) zarch=arm64 ; carch=aarch64 ;; \
        *) echo "unsupported arch ${TARGETARCH}" >&2 ; exit 1 ;; \
      esac \
    ; mkdir -p /out/opt/zapret2 /out/usr/local/bin ; cd /out/opt/zapret2 \
    ; curl -fL "https://github.com/bol-van/zapret2/releases/download/${REVISION}/zapret2-${REVISION}.tar.gz" | \
        tar xzf - --strip-components=1 --wildcards \
            '*/lua/*.lua' \
            '*/files/fake' \
            '*/blockcheck2.sh' \
            '*/blockcheck2.d' \
            '*/common' \
            "*/binaries/linux-${zarch}/nfqws2" \
            "*/binaries/linux-${zarch}/mdig" \
    ; mkdir -p nfq2 mdig \
    ; mv "binaries/linux-${zarch}/nfqws2" nfq2/nfqws2 \
    ; mv "binaries/linux-${zarch}/mdig" mdig/mdig \
    ; rm -r binaries \
    ; ln -s /opt/zapret2/nfq2/nfqws2 /out/usr/local/bin/nfqws2 \
    ; ln -s /opt/zapret2/blockcheck2.sh /out/usr/local/bin/blockcheck2 \
    ; curl -fL "https://github.com/stunnel/static-curl/releases/download/${CURL_VERSION}/curl-linux-${carch}-musl-${CURL_VERSION}.tar.xz" | \
        tar xJf - -C /out/usr/local/bin curl

FROM alpine:${BASE_VER}

# netcat-openbsd is needed by blockcheck2
RUN apk add --no-cache \
    nftables \
    bash \
    netcat-openbsd \
    dumb-init \
    ;

ENV ZAPRET_BASE=/opt/zapret2

COPY --from=builder /out/ /
COPY ./nftables.nft ./entrypoint /
ENTRYPOINT [ "/entrypoint" ]
