#!/usr/bin/env bash

set -eu -o pipefail
DNSMAP_MARK=0x4
DNSMAP_UPSTREAM_DNS=8.8.8.8

ip tuntap add mode tun dev tun0
ip addr add 198.168.18.1/31 dev tun0
ip link set dev tun0 up

mkdir -p /etc/iproute2
echo '1000 tun0' >>/etc/iproute2/rt_tables

ip route add default via 198.168.18.1 dev tun0 table tun0
ip rule add fwmark ${DNSMAP_MARK} lookup tun0

# for dnsmap lookups
ip rule add to ${DNSMAP_UPSTREAM_DNS} lookup tun0

/config/nftables.nft
