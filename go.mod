module github.com/stek29/spoofskipper

go 1.25.5

require (
	github.com/ViRb3/wgcf/v2 v2.2.32
	github.com/ViRb3/wgcf/v2/openapi v0.0.0-00010101000000-000000000000
	github.com/sagernet/sing v0.9.4
	github.com/sagernet/sing-box v1.14.1
)

require (
	github.com/cockroachdb/errors v1.14.0 // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/getsentry/sentry-go v0.46.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
)

// wgcf's generated OpenAPI package is not published as an independent module.
// Its own replacement is not inherited by consumers, so use the matching source
// tree as the replacement until wgcf publishes that module separately.
replace github.com/ViRb3/wgcf/v2/openapi => ./third_party/wgcf-openapi
