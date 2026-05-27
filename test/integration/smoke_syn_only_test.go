// SYN-only feasibility smoke test (T0.3). Sister to
// smoke_paqet_baseline_test.go — same harness, narrower flag profile.
//
// Purpose: discover up-front whether paqet's flag-cycling code path is fully
// wired for `local_flag: ["S"]` / `remote_flag: ["S"]` or whether bugs exist
// that Phase 1 must fix. See docs/findings/T0.3-syn-only-feasibility.md for
// the static analysis predicting the outcome.
//
// This file is intentionally a thin shim: the package-level helpers in
// smoke_paqet_baseline_test.go (`skipUnlessRunnable`, `buildCtunBinary`,
// `allocLoopbackPorts`, `renderFixture`, `startCtun`, `startTestHTTPServer`,
// `doHTTPThroughSOCKS5`, etc.) are reused as-is. They were factored
// per-iteration in T0.2 specifically so a second test like this one could
// stand them up unchanged.
//
// T1.5 supersedes this test with a SYN-TFO variant; T4.6 deletes both this
// file and the baseline. Until then it is the canonical home of the SYN-only
// integration probe. If a future runner observes a real failure mode here
// (panic, hang, hard-to-diagnose silent drop), they should add a `t.Skip`
// at the top of `runSynOnlyRoundTrip` with a justification and link to the
// findings doc — but only after observing the failure, not preemptively.

package integration

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Test_Smoke_SynOnly is the SYN-only counterpart to Test_Smoke_PaqetBaseline.
// It boots a ctun server + client configured with `local_flag: ["S"]` and
// `remote_flag: ["S"]` on loopback, then drives an HTTP GET through the
// SOCKS5 listener. A pass demonstrates that paqet's flag-cycling code path
// supports SYN-only end-to-end without any ctun changes; a fail (or hang)
// signals one of the obstacles enumerated in the T0.3 findings doc.
//
// Sub-tests mirror the baseline: two consecutive runs prove teardown is
// clean and the second iteration is not silently reusing leaked state.
//
// To run locally (requires root):
//
//	sudo go test ./test/integration/ -run 'Smoke_SynOnly' -v
func Test_Smoke_SynOnly(t *testing.T) {
	t.Skip("superseded by Test_Smoke_SynTfo; will be deleted in T4.6")
	skipUnlessRunnable(t)

	bin := buildCtunBinary(t)

	t.Run("first-run", func(t *testing.T) {
		runSynOnlyRoundTrip(t, bin)
	})
	t.Run("second-run", func(t *testing.T) {
		runSynOnlyRoundTrip(t, bin)
	})
}

// runSynOnlyRoundTrip is the SYN-only twin of runBaselineRoundTrip. It is a
// near-clone by design: T0.3 must not perturb the baseline harness, and the
// two tests will share a single extracted helper once T1.5 lands and the
// baseline is retired.
//
// TODO(T1.5): collapse this and runBaselineRoundTrip into a single helper
// `runRoundTrip(t, ctunBin, profile)` parameterised by the fixture-name pair
// and any flag-specific assertions. Doing it now would force a churn pass on
// the (currently sole) baseline test that the T0.2 author asked future
// contributors to leave alone.
func runSynOnlyRoundTrip(t *testing.T, ctunBin string) {
	t.Helper()

	tunnelPort, socksPort := allocLoopbackPorts(t)
	iface := lookupTestIface()
	sharedKey := newSharedKey(t)

	const expectedBody = "ctun-syn-only-ok"
	httpAddr := startTestHTTPServer(t, expectedBody)

	scratch := t.TempDir()
	serverCfg := renderFixture(t, "server-s.yaml", filepath.Join(scratch, "server.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})
	clientCfg := renderFixture(t, "client-s.yaml", filepath.Join(scratch, "client.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})

	serverLog := startCtun(t, ctunBin, serverCfg, "server")
	waitFor(t, fmt.Sprintf("server listening on :%d", tunnelPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", tunnelPort)
	}, serverLog)

	clientLog := startCtun(t, ctunBin, clientCfg, "client")
	waitFor(t, fmt.Sprintf("SOCKS5 listening on :%d", socksPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", socksPort)
	}, clientLog)

	body := doHTTPThroughSOCKS5(t, fmt.Sprintf("127.0.0.1:%d", socksPort), "http://"+httpAddr+"/baseline")
	if got := string(body); got != expectedBody {
		t.Fatalf("unexpected body via SYN-only tunnel: got %q want %q", got, expectedBody)
	}
}
