FROM alpine

RUN apk add --no-cache \
    nftables \
    bash \
    dumb-init \
    ;

ENV ZAPRET_DIR=/opt/zapret
ARG REVISION=master

# Download archive and extract only needed files:
#  - binary of nfqws for matching platform
#  - binary fake files
RUN set -e \
    ; apk add --no-cache curl tar \
    ; mkdir -p "${ZAPRET_DIR}" ; cd "${ZAPRET_DIR}" \
    ; curl -L "https://github.com/bol-van/zapret/archive/${REVISION}.tar.gz" | \
        tar xzf - --strip-components=1 --wildcards \
            '*/files/fake' \
            '*'/"binaries/$(uname -m)/nfqws" \
    ; ln -s "${ZAPRET_DIR}/binaries/$(uname -m)/nfqws" /bin/nfqws \
    ; apk del curl tar
    
COPY ./nftables.nft ./entrypoint /
ENTRYPOINT [ "/entrypoint" ]
