local user_config = import 'config.jsonnet';

local default_config = {
  // logging settings -- keep default
  log: {},
  // default dns server to use
  default_dns: {
    type: 'udp',
    server: '77.88.8.8',
  },
  // dns server address of zapret's dnsmap
  zapret_dns: {
    type: 'udp',
    server: '8.8.8.8',
  },

  // define additional dns servers
  extra_dns_servers: [],
  // additional dns.rules: after zapret/antizapret, just before default
  extra_dns_rules: [],

  // settings for tun inbound
  tun: {
    address: '172.19.0.1/30',
  },

  // settings for the dns server inbound
  dns_server: {
    listen: '0.0.0.0',
    listen_port: 53,
  },

  // always block
  // these are blocked to stop apple private dns/private relay,
  // and to stop firefox DoH
  blocked_domains: [
    'mask.icloud.com',
    'mask-h2.icloud.com',
    'mask-canary.icloud.com',
    'mask.apple-dns.net',
    'use-application-dns.net',
  ],

  fakeip_ttl: 300,

  fakeip_dns: {
    inet4_range: '10.206.0.0/20',
    inet6_range: 'fc00::/18',
  },

  // outbound to use for tun traffic
  tun_outbound: 'direct',
  // extra outbounds
  outbounds: [],

  // sing-geosite names to route to zapret
  zapret_geosites: [
    'youtube',
  ],
  // extra rule_sets to route to zapret
  zapret_rule_sets: [],

  // sing-geosite names to route to proxy
  proxy_geosites: [],
  // extra rule_sets to route to proxy
  proxy_rule_sets: [
    // 'local-proxy',
    'antizapret',
  ],

  // extra rule sets
  extra_rule_sets: [
    // example for local rule_set
    // {
    //   tag: 'local-proxy',
    //   type: 'local',
    //   format: 'source',
    //   path: '/config/local-proxy.json',
    // },
    {
      tag: 'antizapret',
      type: 'remote',
      format: 'binary',
      url: 'https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs',
      download_detour: 'direct',
    },
  ],

  // cache settings
  cache_file: {
    enabled: true,
    path: '/data/cache.db',
    store_fakeip: true,
    store_rdrc: true,
    rdrc_timeout: '1h',
  },

  // clash api disabled by default
  clash_api: {},
};

local config = default_config + user_config;

local geosite_rule_sets = [
  {
    tag: 'gs-%s' % geosite_name,
    type: 'remote',
    format: 'binary',
    url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs' % geosite_name,
    download_detour: 'direct',
  }
  for geosite_name in std.uniq(std.sort(
    config.proxy_geosites + config.zapret_geosites
  ))
];

local geosite_tags(names) = ['gs-' + n for n in std.uniq(std.sort(names))];

local proxy_rule_sets = std.sort(config.proxy_rule_sets + geosite_tags(config.proxy_geosites));
local zapret_rule_sets = std.sort(config.zapret_rule_sets + geosite_tags(config.zapret_geosites));
local hijack_rule_sets = std.sort(proxy_rule_sets + zapret_rule_sets);

{
  log: config.log,
  dns: {
    servers: [
      config.default_dns {
        tag: 'default',
      },
      config.zapret_dns {
        tag: 'zapret',
      },
      config.fakeip_dns {
        tag: 'fakeip',
        type: 'fakeip',
      },
    ] + config.extra_dns_servers,
    rules: [
      {
        action: 'predefined',
        rcode: 'NOERROR',
        domain: config.blocked_domains,
      },
      {
        server: 'zapret',
        query_type: ['A', 'AAAA', 'CNAME'],
        rule_set: zapret_rule_sets,
      },
      {
        server: 'fakeip',
        rewrite_ttl: config.fakeip_ttl,
        query_type: ['A', 'AAAA', 'CNAME'],
        rule_set: proxy_rule_sets,
      },
      {
        // block HTTPS and SVCB records for domains which need to be hijacked
        action: 'predefined',
        rcode: 'NOERROR',
        query_type: ['SVCB', 'HTTPS'],
        rule_set: hijack_rule_sets,
      },
    ] + config.extra_dns_rules,
    independent_cache: true,
  },
  inbounds: [
    config.tun {
      type: 'tun',
      tag: 'tun',
      auto_route: true,
      strict_route: true,
    },
    config.dns_server {
      type: 'direct',
      tag: 'dns-server',
      sniff: false,
    },
  ],
  outbounds: config.outbounds + [
    {
      type: 'direct',
      tag: 'direct',
    },
  ],
  route: {
    rules: [
      {
        inbound: 'dns-server',
        action: 'sniff',
      },
      {
        inbound: 'dns-server',
        protocol: 'dns',
        action: 'hijack-dns',
      },
      {
        ip_is_private: true,
        outbound: 'direct',
      },
      {
        inbound: 'tun',
        outbound: config.tun_outbound,
        // TODO: allow multiple fakeip ranges with smart routing
        // ip_cidr: [
        //   config.fakeip_dns.inet4_range,
        //   config.fakeip_dns.inet6_range,
        // ],
      },
    ],
    rule_set: config.extra_rule_sets + geosite_rule_sets,
    auto_detect_interface: true,
    default_domain_resolver: {
      server: 'default',
    },
  },
  experimental: {
    cache_file: config.cache_file,
    clash_api: config.clash_api,
  },
}
