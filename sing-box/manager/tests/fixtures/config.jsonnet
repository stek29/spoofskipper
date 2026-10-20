local sub_data = std.parseJson(importstr 'local-subs.json');
{
  log: { level: 'warn' },
  inbounds: [],
  outbounds: [{ type: 'selector', tag: 'proxy_main', outbounds: std.objectFields(sub_data.groups) }] +
    [{ type: 'urltest', tag: k, outbounds: sub_data.groups[k], url: 'http://127.0.0.1:1/' }
      for k in std.objectFields(sub_data.groups)] + sub_data.outbounds,
  route: { final: 'proxy_main' },
  experimental: {clash_api: {external_controller: '127.0.0.1:19090', secret: 'synthetic-test-secret'}},
}
