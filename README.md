# spoofskipper
a set of containers to bypass censorship

## components

### [dnsmap](https://github.com/stek29/myazvpn/tree/main/dnsmap)
Proxying dns server, which manages nftables NAT mappings for all of resolved domains

### [zapret](https://github.com/bol-van/zapret)

> A stand-alone (without 3rd party servers) DPI circumvention tool

used in combination with dnsmap for some bypasses

### [sing-box](https://sing-box.sagernet.org)

core part - manages dns routing:
- to be proxied -- responds with `fakeip` addresses (same as dnsmap, but implemented inside `sing-box`)
- to be zapret'ed -- forwards to `dnsmap` running in `zapret` container
- others -- forwarded to upstream resolver, returned as-is

and runs tunnels themselves. it's expected that its `fakeip` range will be routed into the container somehow,
so it can provide automatic tunneling of that address range

## how to run

### configure
example config
```jsonnet
// config/sing/config.jsonnet
{
  default_dns: {
    address: 'https://77.88.8.8/dns-query',
  },
  zapret_dns: {
    address: '192.168.1.2',
  },

  tun_outbound: 'proxy',

  outbounds: [
    {
      tag: 'proxy',
      // your proxy server config
    },
  ],

  zapret_geosites: [
    'youtube',
  ],

  proxy_geosites: [
    'openai',
    'notion',
  ],
  proxy_rule_sets: [
    'antizapret',
    'local-proxy',
  ],

  extra_rule_sets: [
    {
      tag: 'local-proxy',
      type: 'local',
      format: 'source',
      path: '/config/local-proxy.json',
    },
    {
      tag: 'antizapret',
      type: 'remote',
      format: 'binary',
      url: 'https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs',
      download_detour: 'direct',
    },
  ],
}
```

### network

expose containers into external network, while keeping them in their netns.

set up routing on host network, or use different network type, for example -- macvlan:
```yml
# docker-compose.macvlan.yml
services:
  zapret:
    networks:
      default:
        ipv4_address: '192.168.1.2'
  sing-tun:
    networks:
      default:
        ipv4_address: '192.168.1.3'

networks:
  default:
    driver: macvlan
    driver_opts:
      parent: eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: '192.168.1.1'
          ip_range: 192.168.1.0/24
```

route `fakeip` and `dnsmap` ranges for corresponding containers on your network (static routes are enough)

### run
just normal docker compose

build images first -- they're not in registry yet:
```sh
docker compose -f docker-compose.build.yml build
```

then run:
```sh
docker compose up -d
```

or with overrides:
```sh
docker compose -f docker-compose.yml -f docker-compose.macvlan.yml up -d
```

## disclaimer
This project is provided “as is”, without any warranties or liabilities. Use at your own risk.
See LICENSE.

## acknowledgements

This project was inspired by the work of the following projects:
- [Antizapret](https://antizapret.prostovpn.org) ([code](https://bitbucket.org/anticensority/workspace/repositories/))

This project uses following projects and relies on them:
- [bol-van/zapret](https://github.com/bol-van/zapret)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)

Special thanks to the developers of these projects for their invaluable contributions.

It also relies on my prior work from [myazvpn](https://github.com/stek29/myazvpn), which might still be more suitable in some scenarios.
