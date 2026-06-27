# shellcheck shell=bash
# shellcheck disable=SC2034
NFQWS_ARGS=(
    "--qnum=200"
)

# shellcheck disable=SC2034
NFQWS_INSTANCES=(
    "--filter-tcp=80,443 --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls-mod=rnd,rndsni,padencap --wssize 1:6"
    "--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6"
    "--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=/config/zapret/quic_initial_dbankcloud_ru.bin --dpi-desync-fake-stun=/config/zapret/quic_initial_dbankcloud_ru.bin --dpi-desync-repeats=6"
)
