# shellcheck shell=bash
# shellcheck disable=SC2034,SC2054
# nfqws2 options, one per element. Profiles are separated with --new.
# lua libraries are loaded by the entrypoint.
NFQWS2_OPTS=(
  --qnum=200
  --blob=quic_dbank:@/config/zapret/quic_initial_dbankcloud_ru.bin

  # plain http
  --filter-tcp=80 --filter-l7=http
  --lua-desync=fake:blob=fake_default_http:tcp_md5:ip_autottl=2,3-20:ip6_autottl=2,3-20
  --lua-desync=multisplit:pos=2

  # tls: no l7 filter so wssize sees the handshake
  --new --filter-tcp=443
  --lua-desync=wssize:wsize=1:scale=6
  --payload=tls_client_hello
  --lua-desync=multidisorder:pos=1,midsld

  # quic
  --new --filter-udp=443 --filter-l7=quic
  --lua-desync=fake:blob=fake_default_quic:repeats=6

  # discord voice / stun
  --new --filter-udp=590-1400,3478-3497,19294-19344,50000-50100 --filter-l7=discord,stun
  --lua-desync=fake:blob=quic_dbank:repeats=6
)
