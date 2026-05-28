// Phase-1 SYN-TFO end-to-end smoke test (T1.5). Boots the ctun client + server
// with the syntfo transport selected explicitly, drives an HTTP GET through
// the SOCKS5 listener, and asserts that the tunnel's SYN packets on loopback
// carry a TCP option of Kind=34, OptionLength=10 — the on-wire signature of
// the Phase-1 transport.
//
// This is the canonical Phase-1 integration test. T4.5 will wire it into CI.
// Smoke_PaqetBaseline (T0.2) and Smoke_SynOnly (T0.3) are superseded by it
// and now skip with a quarantine message; T4.6 deletes the predecessor files.
//
// The test reuses the helpers introduced in T0.2 (skipUnlessRunnable,
// buildCtunBinary, allocLoopbackPorts, renderFixture, startCtun,
// startTestHTTPServer, doHTTPThroughSOCKS5) and the new startSniffer helper
// from pcap_helpers.go.

package integration

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ctun/internal/transport/syntfo"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Test_Smoke_SynTfo boots client + server with `transport_impl: "syn-tfo"` and
// asserts:
//
//  1. An HTTP GET through the SOCKS5 listener returns the expected body.
//  2. At least one SYN packet captured on loopback carries a TCP option with
//     Kind=34 and OptionLength=10 (the TFO option the syntfo transport stamps
//     on every outbound SYN — see internal/transport/syntfo/send.go).
//
// Subtests `first-run` and `second-run` exercise the same path twice in a
// single `go test` invocation. The DoD's "passes deterministically twice in
// a row" gate is satisfied by both subtests succeeding inside one run —
// teardown leaks (port reuse, lingering subprocesses, pcap handles) would
// surface on the second iteration.
//
// To run locally (requires root):
//
//	sudo go test ./test/integration/ -run 'Smoke_SynTfo' -v
func Test_Smoke_SynTfo(t *testing.T) {
	skipUnlessRunnable(t)

	bin := buildCtunBinary(t)

	t.Run("first-run", func(t *testing.T) {
		runSynTfoRoundTrip(t, bin)
	})
	t.Run("second-run", func(t *testing.T) {
		runSynTfoRoundTrip(t, bin)
	})
}

// runSynTfoRoundTrip is the per-iteration body. It arms the pcap sniffer
// BEFORE the client starts so the SYNs that establish the tunnel are
// captured, then drives the HTTP round trip, stops the sniffer, and runs the
// "at least one SYN had a TFO option" assertion.
//
// Each iteration gets its own free port pair, shared key, and tempdir — there
// is no global state between iterations.
func runSynTfoRoundTrip(t *testing.T, ctunBin string) {
	t.Helper()

	tunnelPort, socksPort := allocLoopbackPorts(t)
	iface := lookupTestIface()
	sharedKey := newSharedKey(t)

	// HTTP server first — the SYN-side server has somewhere to dial as soon
	// as a SOCKS5 CONNECT arrives.
	const expectedBody = "ctun-syn-tfo-ok"
	httpAddr := startTestHTTPServer(t, expectedBody)

	// Materialise YAML fixtures with per-iteration parameters.
	scratch := t.TempDir()
	serverCfg := renderFixture(t, "server-syntfo.yaml", filepath.Join(scratch, "server.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})
	clientCfg := renderFixture(t, "client-syntfo.yaml", filepath.Join(scratch, "client.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})

	// Start the server first so the tunnel port is listening before any SYNs
	// arrive at it. The SYN-TFO server has no kernel TCP listener on the
	// tunnel port — only pcap handles — so we probe the log for the readiness
	// line instead of a TCP dial. See waitForLogSubstring's doc.
	serverLog := startCtun(t, ctunBin, serverCfg, "server")
	waitForLogSubstring(t, "Server started", 10*time.Second, serverLog)

	// Arm the sniffer BEFORE the client boots. We capture every TCP packet
	// on the tunnel port so the client-side SYNs (with the TFO option) land
	// in our packet channel. Filtering by destination port keeps the count
	// low; loopback runs are noisy if we accept everything.
	bpf := fmt.Sprintf("tcp and port %d", tunnelPort)
	packets, stopSniffer := startSniffer(t, snifferConfig{
		Iface:    iface,
		BPF:      bpf,
		Snaplen:  65535,
		Timeout:  250 * time.Millisecond,
		Duration: 15 * time.Second,
	})
	// Cleanup runs in reverse: stop the sniffer first so the goroutine
	// unwinds before the t.TempDir / subprocess teardown executes.
	t.Cleanup(stopSniffer)

	clientLog := startCtun(t, ctunBin, clientCfg, "client")
	waitFor(t, fmt.Sprintf("SOCKS5 listening on :%d", socksPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", socksPort)
	}, clientLog)

	// Drive the HTTP request through the SOCKS5 listener. This is what
	// generates the SYN traffic the sniffer is recording.
	body := doHTTPThroughSOCKS5(t, fmt.Sprintf("127.0.0.1:%d", socksPort), "http://"+httpAddr+"/baseline")
	if got := string(body); got != expectedBody {
		t.Fatalf("unexpected body via SYN-TFO tunnel: got %q want %q", got, expectedBody)
	}

	// The HTTP round trip completed, so every SYN the tunnel needed is
	// already on the wire. Stop the sniffer explicitly (the t.Cleanup is
	// still installed as a safety net) and drain the packet channel into
	// the assertion.
	stopSniffer()
	assertSYNHasTFOOption(t, packets, bpf)
}

// assertSYNHasTFOOption drains packets from the sniffer and fails if no SYN
// packet carrying a Kind=34 option of length 10 is observed. Failure messages
// include the total packet count, the SYN packet count, and the option list
// of the first few SYNs so the diagnostic is actionable without rerunning.
//
// We accept either an Ethernet-framed SYN (Linux lo) or a DLT_NULL/Loopback
// SYN (macOS lo0) by always pulling the TCP layer via
// packet.Layer(layers.LayerTypeTCP) rather than indexing into a frame at a
// hardcoded offset.
//
// The Kind and OptionLength checks use the exported syntfo constants so the
// test fails to compile (rather than silently passing) if anyone bumps the
// option layout without also bumping the smoke test.
func assertSYNHasTFOOption(t *testing.T, packets <-chan gopacket.Packet, bpf string) {
	t.Helper()

	const previewSYNs = 3

	totalPackets := 0
	synCount := 0
	previewOptions := make([][]layers.TCPOption, 0, previewSYNs)

	for pkt := range packets {
		totalPackets++

		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}
		if !tcp.SYN {
			continue
		}
		synCount++
		if len(previewOptions) < previewSYNs {
			optsCopy := make([]layers.TCPOption, len(tcp.Options))
			copy(optsCopy, tcp.Options)
			previewOptions = append(previewOptions, optsCopy)
		}

		for _, opt := range tcp.Options {
			if opt.OptionType == syntfo.TFOOptionKind && opt.OptionLength == syntfo.TFOOptionLength {
				return
			}
		}
	}

	t.Fatalf(
		"no SYN with Kind=%d (len=%d) seen on bpf=%q: captured=%d, syns=%d, first-SYN-options=%s",
		uint8(syntfo.TFOOptionKind), syntfo.TFOOptionLength, bpf, totalPackets, synCount,
		formatOptionPreview(previewOptions),
	)
}

// formatOptionPreview renders a compact "[kind=N,len=M,...]; [...]" summary
// of the TCP options observed in the first few SYNs. Goal: human-readable
// failure diagnostic that doesn't require recapturing the packets.
func formatOptionPreview(perSYN [][]layers.TCPOption) string {
	if len(perSYN) == 0 {
		return "(none)"
	}
	var b strings.Builder
	for i, opts := range perSYN {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteByte('[')
		for j, opt := range opts {
			if j > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "kind=%d,len=%d", uint8(opt.OptionType), opt.OptionLength)
		}
		b.WriteByte(']')
	}
	return b.String()
}
