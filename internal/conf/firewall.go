package conf

import (
	"fmt"
	"slices"
)

// Firewall configures ctun's automatic host-firewall rule management.
//
// ctun crafts raw TCP packets via libpcap; the host kernel must be told to
// ignore them or it will RST the synthetic flow. paqet documented a manual
// iptables recipe in its README (and ctun preserves that in
// example/server.yaml.example); the firewall block here lets ctun install
// the equivalent rules automatically at startup and remove them on
// shutdown.
//
// Defaults: Auto=true, Backend="auto". "auto" selects the per-OS backend
// at runtime (iptables on Linux, pf on macOS, netsh on Windows). Setting
// Auto=false disables automatic rule management entirely — operators who
// run their own configuration management should use this.
//
// T4.1 introduces this config block and the Linux backend; T4.2 wires the
// macOS (pf) backend; T4.3 wires the Windows (netsh) backend; T4.4 wires
// the runtime selection into cmd/run/{server,client}.go. Setting these
// fields today is accepted by the validator but not yet consumed by the
// run command — that's deliberate, so YAML written against this schema
// stays valid as later tasks land.
type Firewall struct {
	// Auto enables automatic install of firewall rules at startup and
	// removal at shutdown (SIGINT/SIGTERM). Default true.
	//
	// Modelled as *bool so we can distinguish "field absent" (defaults to
	// true) from "field present and explicitly false" (operator disabled
	// it). A plain bool would collapse those two cases.
	Auto_ *bool `yaml:"auto"`

	// Backend selects which firewall implementation to use:
	//   - "auto"     : pick per-OS (iptables on Linux, pf on macOS, netsh on Windows)
	//   - "iptables" : force iptables (Linux only)
	//   - "pf"       : force pf (macOS only)
	//   - "netsh"    : force netsh (Windows only)
	//   - "none"     : explicit no-op; equivalent to Auto=false
	// Default "auto".
	Backend string `yaml:"backend"`

	// Auto is the resolved boolean form of Auto_, populated by
	// setDefaults. Consumers read this; the YAML-bound *bool is internal.
	Auto bool `yaml:"-"`
}

// validFirewallBackends is the canonical list of accepted Backend values.
// Kept in one place so the validator and any future help text stay in sync.
var validFirewallBackends = []string{"auto", "iptables", "pf", "netsh", "none"}

func (f *Firewall) setDefaults() {
	if f.Auto_ == nil {
		// Field absent — default to enabled.
		f.Auto = true
	} else {
		f.Auto = *f.Auto_
	}
	if f.Backend == "" {
		f.Backend = "auto"
	}
}

func (f *Firewall) validate() []error {
	var errs []error
	if !slices.Contains(validFirewallBackends, f.Backend) {
		errs = append(errs, fmt.Errorf("firewall.backend %q is not supported; valid values are: %v", f.Backend, validFirewallBackends))
	}
	return errs
}
