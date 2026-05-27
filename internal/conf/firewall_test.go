package conf

import (
	"strings"
	"testing"
)

// TestFirewall_DefaultsWhenAbsent verifies that an unset firewall block
// resolves to (Auto=true, Backend="auto") — ctun ships turnkey, so the
// absence of the block must still install rules.
func TestFirewall_DefaultsWhenAbsent(t *testing.T) {
	var f Firewall
	f.setDefaults()
	if !f.Auto {
		t.Errorf("Auto default should be true when field absent; got %v", f.Auto)
	}
	if f.Backend != "auto" {
		t.Errorf("Backend default should be \"auto\"; got %q", f.Backend)
	}
}

// TestFirewall_ExplicitFalseRespected verifies that operators who set
// auto: false in YAML actually disable auto-management. A previous
// implementation used a plain bool that collapsed "absent" and "false"
// into the same zero value; the *bool pattern in firewall.go exists to
// avoid that.
func TestFirewall_ExplicitFalseRespected(t *testing.T) {
	no := false
	f := Firewall{Auto_: &no}
	f.setDefaults()
	if f.Auto {
		t.Errorf("Auto=false in YAML should resolve to false; got true")
	}
	// Backend still gets its default.
	if f.Backend != "auto" {
		t.Errorf("Backend default should be \"auto\"; got %q", f.Backend)
	}
}

// TestFirewall_ValidateBackend pins the accepted backend strings and that
// the error message lists them so operators see the fix without spelunking.
func TestFirewall_ValidateBackend(t *testing.T) {
	good := []string{"auto", "iptables", "pf", "netsh", "none"}
	for _, b := range good {
		f := Firewall{Backend: b}
		if errs := f.validate(); len(errs) != 0 {
			t.Errorf("backend %q should be accepted; got errors: %v", b, errs)
		}
	}

	f := Firewall{Backend: "ufw"}
	errs := f.validate()
	if len(errs) == 0 {
		t.Fatalf("backend \"ufw\" should be rejected")
	}
	msg := errs[0].Error()
	for _, b := range good {
		if !strings.Contains(msg, b) {
			t.Errorf("validation error should list valid backend %q; got: %s", b, msg)
		}
	}
}
