// warpgen provisions one Cloudflare WARP registration and writes a sing-box
// WireGuard endpoint plus its recovery state.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/stek29/spoofskipper/internal/warpgen"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warpgen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("warpgen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	output := flags.String("output", "warp.json", "path for the generated sing-box endpoint")
	state := flags.String("state", "warp-state.json", "path for the WARP recovery state")
	tag := flags.String("tag", warpgen.DefaultTag, "sing-box endpoint tag")
	detour := flags.String("detour", "", "optional outbound tag used to dial the WARP peer")
	force := flags.Bool("force", false, "overwrite existing output and state files")
	acceptTOS := flags.Bool("accept-tos", false, "accept Cloudflare WARP Terms of Service")
	regenerate := flags.Bool("regenerate", false, "regenerate the endpoint from the existing recovery state")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *regenerate {
		if filepath.Clean(*output) == filepath.Clean(*state) {
			return errors.New("output and state paths must differ")
		}
		stateData, err := warpgen.LoadState(*state)
		if err != nil {
			return err
		}
		registration, err := warpgen.Refresh(stateData)
		if err != nil {
			return err
		}
		parsed, err := warpgen.ParseRegistration(registration)
		if err != nil {
			return err
		}
		endpoint, err := warpgen.NewEndpoint(parsed, stateData.PrivateKey, *tag, *detour)
		if err != nil {
			return err
		}
		if err := warpgen.WriteEndpoint(endpoint, *output, *force); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "WARP endpoint regenerated from %s and written to %s\n", *state, *output)
		return nil
	}
	if !*acceptTOS {
		return errors.New("--accept-tos is required before registering a WARP device")
	}
	if err := warpgen.PrepareDestinationPaths(*force, *output, *state); err != nil {
		return err
	}

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("generate WireGuard private key: %w", err)
	}
	registration, err := warpgen.Register(privateKey)
	if err != nil {
		return err
	}
	parsed, err := warpgen.ParseRegistration(registration)
	if err != nil {
		return err
	}
	endpoint, err := warpgen.NewEndpoint(parsed, privateKey.String(), *tag, *detour)
	if err != nil {
		return err
	}
	if err := warpgen.WriteOutputs(endpoint, warpgen.NewState(registration, privateKey.String()), *output, *state, *force); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "WARP endpoint written to %s; recovery state written to %s\n", *output, *state)
	return nil
}
