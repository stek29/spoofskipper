// Package warpgen creates sing-box WireGuard endpoints from Cloudflare WARP
// registrations. It deliberately keeps Cloudflare registration separate from
// endpoint construction so that no network access is needed to test it.
package warpgen

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	DefaultTag  = "warp"
	DefaultPort = 2408
)

// Registration is the subset of a WARP registration needed for output and
// future account recovery. It intentionally excludes the raw API response.
type Registration struct {
	DeviceID    string
	AccessToken string
	LicenseKey  string
	ClientID    string
	IPv4        string
	IPv6        string
	Peers       []Peer
}

type Peer struct {
	PublicKey string
	Endpoint  string
}

// ParsedRegistration is registration data ready to build into a sing-box
// endpoint.
type ParsedRegistration struct {
	Registration
	Reserved []uint8
	Host     string
	Port     uint16
}

func ParseRegistration(reg Registration) (ParsedRegistration, error) {
	if strings.TrimSpace(reg.DeviceID) == "" {
		return ParsedRegistration{}, fmt.Errorf("WARP registration has no device ID")
	}
	if strings.TrimSpace(reg.AccessToken) == "" {
		return ParsedRegistration{}, fmt.Errorf("WARP registration has no access token")
	}
	if strings.TrimSpace(reg.ClientID) == "" {
		return ParsedRegistration{}, fmt.Errorf("WARP registration has no client_id")
	}
	if strings.TrimSpace(reg.IPv4) == "" {
		return ParsedRegistration{}, fmt.Errorf("WARP registration has no IPv4 address")
	}
	if strings.TrimSpace(reg.IPv6) == "" {
		return ParsedRegistration{}, fmt.Errorf("WARP registration has no IPv6 address")
	}
	if len(reg.Peers) == 0 {
		return ParsedRegistration{}, fmt.Errorf("WARP registration has no peers")
	}
	if strings.TrimSpace(reg.Peers[0].PublicKey) == "" {
		return ParsedRegistration{}, fmt.Errorf("WARP registration peer has no public key")
	}

	reserved, err := ReservedFromClientID(reg.ClientID)
	if err != nil {
		return ParsedRegistration{}, err
	}
	host, port, err := ParseEndpoint(reg.Peers[0].Endpoint)
	if err != nil {
		return ParsedRegistration{}, err
	}
	if _, err = endpointPrefix(reg.IPv4, 32); err != nil {
		return ParsedRegistration{}, fmt.Errorf("invalid WARP IPv4 address: %w", err)
	}
	if _, err = endpointPrefix(reg.IPv6, 128); err != nil {
		return ParsedRegistration{}, fmt.Errorf("invalid WARP IPv6 address: %w", err)
	}

	return ParsedRegistration{
		Registration: reg,
		Reserved:     reserved,
		Host:         host,
		Port:         port,
	}, nil
}

func ReservedFromClientID(clientID string) ([]uint8, error) {
	reserved, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		return nil, fmt.Errorf("decode WARP client_id: %w", err)
	}
	if len(reserved) == 0 {
		return nil, fmt.Errorf("WARP client_id decodes to no reserved bytes")
	}
	if len(reserved) != 3 {
		return nil, fmt.Errorf("WARP client_id must decode to exactly 3 reserved bytes, got %d", len(reserved))
	}
	return reserved, nil
}

func ParseEndpoint(value string) (string, uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("WARP peer endpoint is empty")
	}

	host, portText, err := net.SplitHostPort(value)
	if err == nil {
		if host == "" {
			return "", 0, fmt.Errorf("WARP peer endpoint has an empty host")
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return "", 0, fmt.Errorf("WARP peer endpoint has an invalid port %q", portText)
		}
		return host, uint16(port), nil
	}

	// A bare host or IP address is accepted with Cloudflare's WARP port.
	if strings.ContainsAny(value, "[] ") {
		return "", 0, fmt.Errorf("invalid WARP peer endpoint %q", value)
	}
	return value, DefaultPort, nil
}

func endpointPrefix(value string, bits int) (netip.Prefix, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, err
	}
	if bits == 32 && !address.Is4() {
		return netip.Prefix{}, fmt.Errorf("expected IPv4 address")
	}
	if bits == 128 && !address.Is6() {
		return netip.Prefix{}, fmt.Errorf("expected IPv6 address")
	}
	return netip.PrefixFrom(address, bits), nil
}
