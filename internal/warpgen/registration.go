package warpgen

import (
	"fmt"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	"github.com/ViRb3/wgcf/v2/openapi"
	"github.com/ViRb3/wgcf/v2/wireguard"
)

// Register asks wgcf to create a PC WARP registration. The wgcf library owns
// API versions, request shapes, headers, and TLS compatibility behavior.
func Register(privateKey *wireguard.Key) (Registration, error) {
	if privateKey == nil {
		return Registration{}, fmt.Errorf("WireGuard private key is nil")
	}
	registration, err := cloudflare.Register(privateKey.Public(), "PC")
	if err != nil {
		return Registration{}, fmt.Errorf("register WARP device: %w", err)
	}
	return RegistrationFromWGCF(registration)
}

func RegistrationFromWGCF(registration *openapi.Register200Response) (Registration, error) {
	if registration == nil {
		return Registration{}, fmt.Errorf("WARP registration response is nil")
	}
	peers := make([]Peer, len(registration.Config.Peers))
	for index, peer := range registration.Config.Peers {
		peers[index] = Peer{
			PublicKey: peer.PublicKey,
			Endpoint:  peer.Endpoint.Host,
		}
	}
	return Registration{
		DeviceID:    registration.Id,
		AccessToken: registration.Token,
		LicenseKey:  registration.Account.License,
		ClientID:    registration.Config.ClientId,
		IPv4:        registration.Config.Interface.Addresses.V4,
		IPv6:        registration.Config.Interface.Addresses.V6,
		Peers:       peers,
	}, nil
}
