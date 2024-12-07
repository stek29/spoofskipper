# shellcheck shell=bash
# shellcheck disable=SC2034
NFQWS_INSTANCES=(
    "${NFQWS_DEFAULT_ARGS:-} --qnum=200 --dpi-desync=fake,split2 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig --dpi-desync-fake-tls=/opt/zapret/files/fake/tls_clienthello_www_google_com.bin"
    "${NFQWS_DEFAULT_ARGS:-} --qnum=210 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-any-protocol"
)
