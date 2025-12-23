FROM alpine:3.23.2

RUN apk add --no-cache \
    nftables \
    bash \
    dumb-init \
    ;

ENV ZAPRET_DIR=/opt/zapret
ARG REVISION

# Download archive and extract only needed files:
#  - binary of nfqws for matching platform
#  - binary fake files
RUN set -e \
    ; archdir="linux-$(uname -m | sed 's/aarch64/arm64/')" \
    ; apk add --no-cache curl tar \
    ; mkdir -p "${ZAPRET_DIR}" ; cd "${ZAPRET_DIR}" \
    ; curl -L "https://github.com/bol-van/zapret/releases/download/${REVISION}/zapret-${REVISION}.tar.gz" | \
        tar xzf - --strip-components=1 --wildcards \
            '*/files/fake' \
            '*'/"binaries/${archdir}/nfqws" \
    ; ln -s "${ZAPRET_DIR}/binaries/${archdir}/nfqws" /bin/nfqws \
    ; apk del curl tar
    
COPY ./nftables.nft ./entrypoint /
ENTRYPOINT [ "/entrypoint" ]
