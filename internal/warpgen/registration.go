package warpgen

import (
	"fmt"
	"net"
	"strconv"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	"github.com/ViRb3/wgcf/v2/config"
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
	return registrationFromConfig(registration.Config, registration.Id, registration.Token, registration.Account.GetLicense())
}

// Refresh retrieves the current connection parameters for the registered WARP
// device in state. It does not create, modify, or delete a WARP device.
func Refresh(state State) (Registration, error) {
	if err := state.Validate(); err != nil {
		return Registration{}, err
	}
	device, err := cloudflare.GetSourceDevice(&config.Context{
		DeviceId:    state.DeviceID,
		AccessToken: state.AccessToken,
		PrivateKey:  state.PrivateKey,
		LicenseKey:  state.LicenseKey,
	})
	if err != nil {
		return Registration{}, fmt.Errorf("get current WARP device configuration: %w", err)
	}
	if device == nil {
		return Registration{}, fmt.Errorf("WARP device response is nil")
	}
	return registrationFromConfig(device.Config, state.DeviceID, state.AccessToken, state.LicenseKey)
}

func registrationFromConfig(configuration *openapi.Config, deviceID, accessToken, licenseKey string) (Registration, error) {
	if configuration == nil {
		return Registration{}, fmt.Errorf("WARP response has no config")
	}
	peers := make([]Peer, len(configuration.Peers))
	for index, peer := range configuration.Peers {
		endpoint, err := peerEndpoint(peer.Endpoint)
		if err != nil {
			return Registration{}, fmt.Errorf("get WARP peer endpoint: %w", err)
		}
		peers[index] = Peer{
			PublicKey: peer.PublicKey,
			Endpoint:  endpoint,
		}
	}
	return Registration{
		DeviceID:    deviceID,
		AccessToken: accessToken,
		LicenseKey:  licenseKey,
		ClientID:    configuration.ClientId,
		IPv4:        configuration.Interface.Addresses.V4,
		IPv6:        configuration.Interface.Addresses.V6,
		Peers:       peers,
	}, nil
}

func peerEndpoint(endpoint openapi.Endpoint) (string, error) {
	host := endpoint.GetHost()
	if host == "" {
		if endpoint.V4 != "" {
			host = endpoint.V4
		} else {
			host = endpoint.V6
		}
	}
	if host == "" {
		return "", fmt.Errorf("WARP response did not contain a peer host")
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	port := DefaultPort
	if len(endpoint.Ports) > 0 {
		if endpoint.Ports[0] < 1 || endpoint.Ports[0] > 65535 {
			return "", fmt.Errorf("WARP response has invalid peer port %d", endpoint.Ports[0])
		}
		port = int(endpoint.Ports[0])
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
