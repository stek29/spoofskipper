# spoofskipper
a set of containers to bypass censorship

## components

### [unbound](https://unbound.net/)

Provides DNS64 to use with Tayga

### [TAYGA](https://github.com/apalrd/tayga)

NAT64 implemented in user-space with tun

### [zapret2](https://github.com/bol-van/zapret2)

> A stand-alone (without 3rd party servers) DPI circumvention tool

used in combination with unbound and tayga for some bypasses.
`nfqws2` strategy is configured in `config/zapret2.sh` as the `NFQWS2_OPTS` array
(profiles separated with `--new`, see the [zapret2 manual](https://github.com/bol-van/zapret2/blob/master/docs/manual.en.md)).
extra global options (e.g. `--debug=1`) can be passed with the `NFQWS2_EXTRA_ARGS` env var.

### [sing-box](https://sing-box.sagernet.org)

core part - manages dns routing:
- to be proxied -- responds with `fakeip` addresses
- to be zapret'ed -- forwards to `unbound` running in `zapret` container in dns64 only mode
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

The endpoint tag defaults to `warp` and can be changed with `--tag`. Use
`--detour <outbound-tag>` to route the WireGuard peer's dial traffic through an
existing sing-box outbound; omit it to dial the peer directly.

```sh
# docker run --rm -it -v "$PWD:/src" -w /src golang:latest \
go run ./cmd/warpgen \
  --accept-tos \
  --detour proxy \
  --output config/sing/local-warp.json \
  --state config/sing/local-warp-state.json
```

Run the command locally with Go, or remove `# ` from the first line to run it
in Docker instead. The bind mount keeps the generated credential files on the
host. The pinned `wgcf` v2.3.0 module requires Go 1.26 or newer.

To refresh an endpoint for the same WARP device without registering another
device, use the saved state file. This fetches the device's current connection
parameters and rewrites only the endpoint; it leaves the recovery state intact.
Use `--force` only if the endpoint file already exists.

```sh
go run ./cmd/warpgen \
  --regenerate \
  --state config/sing/local-warp-state.json \
  --output config/sing/local-warp.json \
  --detour proxy \
  --force
```

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
        mac_address: '02:ca:fe:ba:be:02'
        ipv6_address: 'fc00:::ca:feff:feba:be02'
        driver_opts:
          com.docker.network.endpoint.sysctls: >-
            net.ipv6.conf.IFNAME.accept_ra=2
  sing-tun:
    networks:
      default:
        ipv4_address: '192.168.1.3'
        mac_address: '02:ca:fe:ba:be:03'
        ipv6_address: 'fc00:::ca:feff:feba:be03'
        driver_opts:
          com.docker.network.endpoint.sysctls: >-
            net.ipv6.conf.IFNAME.accept_ra=2

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
        - subnet: 'fc00::/64'
```

route `fakeip` and `nat64` ranges for corresponding containers on your network (static routes are enough)

### run
just normal docker compose

images are built and published to GHCR from the pinned versions in `.env`.
Each image uses a tag made from the upstream revision and the local package version:

```sh
REVISION_ALPINE_IMAGE=3.24.2
REVISION_ZAPRET2=v1.0.5.2
VERSION_ZAPRET2=1
# ghcr.io/stek29/spoofskipper/zapret2:v1.0.5.2-3.24.2-1
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

### finding a strategy
`blockcheck2` is bundled in the zapret2 image. run it in a one-off container, so the running
`nfqws2` and its nftables rules don't interfere with the tests:
```sh
docker compose run --rm -it --entrypoint blockcheck2 zapret
```

to test over the same network as the deployment (e.g. with the macvlan override), stop `zapret` first
so the static address is free, and pass the same compose files. `unbound` and `tayga` share the network
of `zapret`, so stop them too, otherwise they're left in a stale network namespace after `zapret` restarts:
```sh
docker compose -f docker-compose.yml -f docker-compose.macvlan.yml stop zapret unbound tayga
docker compose -f docker-compose.yml -f docker-compose.macvlan.yml run --rm -it --entrypoint blockcheck2 zapret
docker compose -f docker-compose.yml -f docker-compose.macvlan.yml up -d
```

## disclaimer
This project is provided “as is”, without any warranties or liabilities. Use at your own risk.
See LICENSE.

## acknowledgements

This project was inspired by the work of the following projects:
- [Antizapret](https://antizapret.prostovpn.org) ([code](https://bitbucket.org/anticensority/workspace/repositories/))

This project uses following projects and relies on them:
- [bol-van/zapret2](https://github.com/bol-van/zapret2)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [ViRb3/wgcf](https://github.com/ViRb3/wgcf)
- [savely-krasovsky/antizapret-sing-box](https://github.com/savely-krasovsky/antizapret-sing-box)
- [unbound](https://unbound.net/)
- [apalrd/TAYGA](https://github.com/apalrd/tayga)

Special thanks to the developers of these projects for their invaluable contributions.

It also relies on my prior work from [myazvpn](https://github.com/stek29/myazvpn), which might still be more suitable in some scenarios.
