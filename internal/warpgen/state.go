package warpgen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type State struct {
	Version     int    `json:"version"`
	DeviceID    string `json:"device_id"`
	AccessToken string `json:"access_token"`
	PrivateKey  string `json:"private_key"`
	LicenseKey  string `json:"license_key,omitempty"`
}

func NewState(registration Registration, privateKey string) State {
	return State{
		Version:     1,
		DeviceID:    registration.DeviceID,
		AccessToken: registration.AccessToken,
		PrivateKey:  privateKey,
		LicenseKey:  registration.LicenseKey,
	}
}

// LoadState reads a recovery-state file written by warpgen.
func LoadState(path string) (State, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return State{}, fmt.Errorf("read WARP recovery state: %w", err)
	}
	var state State
	if err := json.Unmarshal(content, &state); err != nil {
		return State{}, fmt.Errorf("decode WARP recovery state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func (state State) Validate() error {
	if state.Version != 1 {
		return fmt.Errorf("unsupported WARP recovery state version %d", state.Version)
	}
	if state.DeviceID == "" {
		return fmt.Errorf("WARP recovery state has no device_id")
	}
	if state.AccessToken == "" {
		return fmt.Errorf("WARP recovery state has no access_token")
	}
	if state.PrivateKey == "" {
		return fmt.Errorf("WARP recovery state has no private_key")
	}
	return nil
}

// PrepareDestinationPaths catches predictable local errors before registering a
// remote WARP device. Both files must either be new or explicitly forced.
func PrepareDestinationPaths(force bool, paths ...string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			return fmt.Errorf("output path is empty")
		}
		path = filepath.Clean(path)
		if _, exists := seen[path]; exists {
			return fmt.Errorf("output and state paths must differ")
		}
		seen[path] = struct{}{}

		directory := filepath.Dir(path)
		info, err := os.Stat(directory)
		if err != nil {
			return fmt.Errorf("stat parent directory for %s: %w", path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("parent path for %s is not a directory", path)
		}
		if info, err = os.Stat(path); err == nil {
			if info.IsDir() {
				return fmt.Errorf("%s is a directory", path)
			}
			if !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", path)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", path, err)
		}
	}
	return nil
}

func WriteOutputs(endpoint Endpoint, state State, outputPath, statePath string, force bool) error {
	if err := PrepareDestinationPaths(force, outputPath, statePath); err != nil {
		return err
	}
	endpointJSON, err := json.MarshalIndent(endpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("encode endpoint: %w", err)
	}
	stateJSON, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	endpointJSON = append(endpointJSON, '\n')
	stateJSON = append(stateJSON, '\n')

	// Persist state first: after a remote registration succeeds, a recoverable
	// registration is more important than a generated convenience config.
	if err := atomicWrite(statePath, stateJSON); err != nil {
		return fmt.Errorf("WARP registration may have been created, but writing state failed: %w", err)
	}
	if err := atomicWrite(outputPath, endpointJSON); err != nil {
		return fmt.Errorf("WARP state was written to %s, but writing endpoint failed: %w", statePath, err)
	}
	return nil
}

// WriteEndpoint writes a regenerated endpoint without changing its recovery
// state. The state file is deliberately kept intact so it remains reusable.
func WriteEndpoint(endpoint Endpoint, outputPath string, force bool) error {
	if err := PrepareDestinationPaths(force, outputPath); err != nil {
		return err
	}
	endpointJSON, err := json.MarshalIndent(endpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("encode endpoint: %w", err)
	}
	return atomicWrite(outputPath, append(endpointJSON, '\n'))
}

func atomicWrite(path string, content []byte) (err error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".warpgen-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if directoryFile, openErr := os.Open(directory); openErr == nil {
		defer directoryFile.Close()
		if syncErr := directoryFile.Sync(); syncErr != nil && syncErr != os.ErrInvalid {
			return syncErr
		}
	}
	return nil
}
