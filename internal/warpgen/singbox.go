package warpgen

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Endpoint is a minimal wrapper around sing-box's WireGuard option type. It
// supplies the endpoint discriminator fields that option.Endpoint normally
// flattens through sing-box's context-aware JSON encoder.
type Endpoint struct {
	Type    string
	Tag     string
	Options option.WireGuardEndpointOptions
}

func NewEndpoint(parsed ParsedRegistration, privateKey, tag, detour string) (Endpoint, error) {
	if tag == "" {
		tag = DefaultTag
	}
	v4, err := endpointPrefix(parsed.IPv4, 32)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid WARP IPv4 address: %w", err)
	}
	v6, err := endpointPrefix(parsed.IPv6, 128)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid WARP IPv6 address: %w", err)
	}
	if privateKey == "" {
		return Endpoint{}, fmt.Errorf("WireGuard private key is empty")
	}

	options := option.WireGuardEndpointOptions{
		MTU:        1280,
		Address:    prefixes(v4, v6),
		PrivateKey: privateKey,
		Peers: []option.WireGuardPeer{
			{
				Address:                     parsed.Host,
				Port:                        parsed.Port,
				PublicKey:                   parsed.Peers[0].PublicKey,
				AllowedIPs:                  prefixes(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")),
				PersistentKeepaliveInterval: 30,
				Reserved:                    parsed.Reserved,
			},
		},
	}
	options.Detour = detour

	return Endpoint{Type: "wireguard", Tag: tag, Options: options}, nil
}

func prefixes(values ...netip.Prefix) badoption.Listable[netip.Prefix] {
	return badoption.Listable[netip.Prefix](values)
}

// MarshalJSON uses sing-box's current option structs for every WireGuard and
// dial field. Its small adapter changes only Reserved: encoding/json encodes
// []uint8 as base64, while sing-box configuration expects numeric byte values.
func (endpoint Endpoint) MarshalJSON() ([]byte, error) {
	optionsJSON, err := json.Marshal(endpoint.Options)
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err = json.Unmarshal(optionsJSON, &result); err != nil {
		return nil, err
	}
	var peers []map[string]json.RawMessage
	if err = json.Unmarshal(result["peers"], &peers); err != nil {
		return nil, err
	}
	for index, peer := range peers {
		if index >= len(endpoint.Options.Peers) || endpoint.Options.Peers[index].Reserved == nil {
			continue
		}
		// Convert through []int to avoid encoding/json's special []byte handling.
		reserved := make([]int, len(endpoint.Options.Peers[index].Reserved))
		for i, value := range endpoint.Options.Peers[index].Reserved {
			reserved[i] = int(value)
		}
		reservedJSON, err := json.Marshal(reserved)
		if err != nil {
			return nil, err
		}
		peer["reserved"] = reservedJSON
	}
	peersJSON, err := json.Marshal(peers)
	if err != nil {
		return nil, err
	}
	result["peers"] = peersJSON
	result["type"], _ = json.Marshal(endpoint.Type)
	result["tag"], _ = json.Marshal(endpoint.Tag)
	return json.Marshal(result)
}
