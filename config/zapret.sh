# shellcheck shell=bash
# shellcheck disable=SC2034
NFQWS_INSTANCES=(
    "${NFQWS_DEFAULT_ARGS:-} --qnum=200 --dpi-desync=split2 --dpi-desync-split-pos=2"
    "${NFQWS_DEFAULT_ARGS:-} --qnum=210 --dpi-desync=fake --dpi-desync-repeats=6"
)
