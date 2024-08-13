FROM golang:1.22 AS build
ARG REVISION=latest
RUN CGO_ENABLED=0 go install github.com/stek29/myazvpn/dnsmap@${REVISION}

FROM scratch
COPY --from=build /go/bin/dnsmap /dnsmap
ENTRYPOINT [ "/dnsmap" ]
