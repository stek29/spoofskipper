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

  // optional top-level sing-box endpoints
  endpoints: [
    // Uncomment after generating config/sing/local-warp.json below:
    // std.parseJson(importstr 'local-warp.json'),
  ],

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

### WARP WireGuard endpoint

`warpgen` registers a WARP device through the `wgcf` library and writes a
current sing-box WireGuard endpoint plus a separate recovery-state file. Both
files contain credentials and are created with mode `0600`.

```sh
go run ./cmd/warpgen \
  --accept-tos \
  --detour proxy \
  --output config/sing/local-warp.json \
  --state config/sing/local-warp-state.json
```

Without a local Go installation, prepend
`docker run --rm -it -v "$PWD:/src" -w /src golang:latest` before the same
`go run` command. The bind mount keeps the generated credential files on the
host. The pinned `wgcf` v2.2.32 module requires Go 1.25 or newer.

`local-*.json` is ignored by Git. In `config/sing/config.jsonnet`, add the
generated endpoint to `endpoints` with:

```jsonnet
endpoints: [
  std.parseJson(importstr 'local-warp.json'),
],
```

The generated entry is an ordinary sing-box endpoint; it can also be supplied
manually when credentials already exist. Its peer dial path may use an existing
outbound through `detour`:

```jsonnet
{
  endpoints: [
    {
      type: 'wireguard',
      tag: 'warp',
      address: [
        '172.16.0.2/32',
        '2606:4700:110:.../128',
      ],
      private_key: '<private-key>',
      peers: [
        {
          address: 'engage.cloudflareclient.com',
          port: 2408,
          public_key: '<peer-public-key>',
          allowed_ips: [
            '0.0.0.0/0',
            '::/0',
          ],
          persistent_keepalive_interval: 30,
          reserved: [123, 45, 67],
        },
      ],
      detour: 'proxy',
    },
  ],

  outbounds: [
    {
      tag: 'proxy',
      // existing proxy outbound config
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

images are built and published to GHCR from the pinned versions in `.env`.
Each image uses a tag made from the upstream revision and the local package version:

```sh
REVISION_ZAPRET=v72.12
VERSION_ZAPRET=1
# ghcr.io/stek29/spoofskipper/zapret:v72.12-1
```

Bump the matching `VERSION_*` when changing the local Dockerfile or entrypoint for an image.
Bump the matching `REVISION_*` when updating the upstream component, and reset or bump `VERSION_*`
as appropriate. The GitHub Actions workflow runs on `.env` changes on `master` and only builds
image tags that are not already present in GHCR.

To build images locally instead:
```sh
docker compose -f docker-compose.build.yml build
```

Run:
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
- [ViRb3/wgcf](https://github.com/ViRb3/wgcf)
- [savely-krasovsky/antizapret-sing-box](https://github.com/savely-krasovsky/antizapret-sing-box)

Special thanks to the developers of these projects for their invaluable contributions.

It also relies on my prior work from [myazvpn](https://github.com/stek29/myazvpn), which might still be more suitable in some scenarios.
