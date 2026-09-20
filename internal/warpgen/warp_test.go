package warpgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ViRb3/wgcf/v2/openapi"
)

func testRegistration() Registration {
	return Registration{
		DeviceID:    "device-id",
		AccessToken: "access-token",
		LicenseKey:  "license-key",
		ClientID:    "AQID",
		IPv4:        "172.16.0.2",
		IPv6:        "2606:4700:110::2",
		Peers: []Peer{{
			PublicKey: "peer-public-key",
			Endpoint:  "engage.cloudflareclient.com:2408",
		}},
	}
}

func TestReservedFromClientID(t *testing.T) {
	reserved, err := ReservedFromClientID("AQID")
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint8{1, 2, 3}; !reflect.DeepEqual(reserved, want) {
		t.Fatalf("reserved = %v, want %v", reserved, want)
	}
	for _, clientID := range []string{"!", "AQI=", ""} {
		if _, err := ReservedFromClientID(clientID); err == nil {
			t.Errorf("ReservedFromClientID(%q) succeeded", clientID)
		}
	}
}

func TestParseRegistrationRejectsIncompleteResponses(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Registration)
	}{
		{"missing peer", func(reg *Registration) { reg.Peers = nil }},
		{"missing peer key", func(reg *Registration) { reg.Peers[0].PublicKey = "" }},
		{"missing client ID", func(reg *Registration) { reg.ClientID = "" }},
		{"missing IPv4", func(reg *Registration) { reg.IPv4 = "" }},
		{"missing IPv6", func(reg *Registration) { reg.IPv6 = "" }},
		{"missing endpoint", func(reg *Registration) { reg.Peers[0].Endpoint = "" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reg := testRegistration()
			test.edit(&reg)
			if _, err := ParseRegistration(reg); err == nil {
				t.Fatal("ParseRegistration succeeded")
			}
		})
	}
}

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		input string
		host  string
		port  uint16
	}{
		{"engage.cloudflareclient.com:2408", "engage.cloudflareclient.com", 2408},
		{"162.159.192.1:2408", "162.159.192.1", 2408},
		{"[2606:4700:d0::a29f:c001]:2408", "2606:4700:d0::a29f:c001", 2408},
		{"engage.cloudflareclient.com", "engage.cloudflareclient.com", DefaultPort},
	}
	for _, test := range cases {
		host, port, err := ParseEndpoint(test.input)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q): %v", test.input, err)
		}
		if host != test.host || port != test.port {
			t.Fatalf("ParseEndpoint(%q) = %q, %d; want %q, %d", test.input, host, port, test.host, test.port)
		}
	}
}

func TestRegistrationFromConfigPreservesPeerPort(t *testing.T) {
	host := "engage.cloudflareclient.com"
	registration, err := registrationFromConfig(&openapi.Config{
		ClientId: "AQID",
		Interface: openapi.ConfigInterface{Addresses: openapi.NetworkAddress{
			V4: "172.16.0.2",
			V6: "2606:4700:110::2",
		}},
		Peers: []openapi.Peer{{
			PublicKey: "peer-public-key",
			Endpoint:  openapi.Endpoint{Host: &host, Ports: []int32{500}},
		}},
	}, "device-id", "access-token", "license-key")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := registration.Peers[0].Endpoint, "engage.cloudflareclient.com:500"; got != want {
		t.Errorf("peer endpoint = %q, want %q", got, want)
	}
}

func TestEndpointJSON(t *testing.T) {
	parsed, err := ParseRegistration(testRegistration())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(parsed, "private-key", "warp", "proxy")
	if err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), `"reserved":"AQID"`) || !strings.Contains(string(content), `"reserved":[1,2,3]`) {
		t.Fatalf("reserved bytes were not encoded as a numeric JSON array: %s", content)
	}
	var decoded map[string]any
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"type": "wireguard", "tag": "warp", "mtu": float64(1280), "detour": "proxy",
	} {
		if decoded[key] != want {
			t.Errorf("%s = %#v, want %#v", key, decoded[key], want)
		}
	}
	addresses := decoded["address"].([]any)
	if addresses[0] != "172.16.0.2/32" || addresses[1] != "2606:4700:110::2/128" {
		t.Errorf("address = %#v", addresses)
	}
	peer := decoded["peers"].([]any)[0].(map[string]any)
	if peer["port"] != float64(2408) || peer["persistent_keepalive_interval"] != float64(30) {
		t.Errorf("peer = %#v", peer)
	}
	if _, hasDetour := peer["detour"]; hasDetour {
		t.Errorf("peer unexpectedly contains detour: %#v", peer)
	}
	allowed := peer["allowed_ips"].([]any)
	if allowed[0] != "0.0.0.0/0" || allowed[1] != "::/0" {
		t.Errorf("allowed_ips = %#v", allowed)
	}

	withoutDetour, err := NewEndpoint(parsed, "private-key", "", "")
	if err != nil {
		t.Fatal(err)
	}
	content, err = json.Marshal(withoutDetour)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), `"detour"`) {
		t.Fatalf("endpoint without a detour contains one: %s", content)
	}
}

func TestWriteOutputsPermissionsAndForce(t *testing.T) {
	parsed, err := ParseRegistration(testRegistration())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(parsed, "private-key", "warp", "")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	output := filepath.Join(directory, "warp.json")
	state := filepath.Join(directory, "warp-state.json")
	if err := WriteOutputs(endpoint, NewState(testRegistration(), "private-key"), output, state, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{output, state} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s permissions = %o, expected 0600", path, info.Mode().Perm())
		}
	}
	if err := WriteOutputs(endpoint, NewState(testRegistration(), "private-key"), output, state, false); err == nil {
		t.Fatal("WriteOutputs overwrote existing files without force")
	}
	if err := WriteOutputs(endpoint, NewState(testRegistration(), "private-key"), output, state, true); err != nil {
		t.Fatalf("WriteOutputs with force: %v", err)
	}
}

func TestLoadStateAndWriteEndpoint(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "warp-state.json")
	state := NewState(testRegistration(), "private-key")
	content, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Errorf("LoadState() = %#v, want %#v", loaded, state)
	}

	output := filepath.Join(directory, "warp.json")
	parsed, err := ParseRegistration(testRegistration())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(parsed, loaded.PrivateKey, "warp", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteEndpoint(endpoint, output, false); err != nil {
		t.Fatal(err)
	}
	stateAfter, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stateAfter) != string(content) {
		t.Fatal("WriteEndpoint changed the recovery state")
	}
}

func TestLoadStateRejectsInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp-state.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"device_id":"device"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("LoadState accepted incomplete state")
	}
}
