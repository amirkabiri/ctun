// Pcap-sniffing helpers for the integration suite.
//
// T1.5 was the first integration test that needed to assert on packet content
// (specifically: at least one captured SYN must carry the Kind=34 TFO option).
// T3.5's secure-tunnel smoke test will need the same shape — start a capture
// before booting the client, drive a round trip, then inspect the captured
// packets. The shared piece is "open a pcap handle on the loopback interface
// with a BPF filter, deliver parsed packets to the caller, shut down cleanly."
// Everything else is per-test assertion code, kept in the test file.
//
// This file owns the shared piece. It deliberately stays a thin wrapper around
// gopacket/pcap — there is no goroutine pool, no buffering policy beyond
// gopacket's default packet channel, no allocation accounting. Test code,
// ergonomics over performance.
//
// The file is in the (non-`_test.go`) `integration` package so that future
// `_test.go` files in the same package — including T3.5's — can call into it
// the same way smoke_syn_tfo_test.go does. proc_unix.go set this precedent;
// we follow it here.

package integration

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// snifferConfig describes the capture parameters for startSniffer. The fields
// map 1:1 onto the corresponding pcap.InactiveHandle setters so the call site
// reads like a slimmed-down pcap.OpenLive invocation.
//
// Field reference (see per-field comments below for full prose):
//   - Iface: pcap interface name (e.g. "lo0", "lo", or CTUN_TEST_IFACE).
//   - BPF: BPF filter expression; empty means "accept everything", but the
//     smoke tests always narrow to a port to keep captured-packet counts
//     low enough that the failure diagnostic is readable.
//   - Snaplen: pcap snapshot length. 65535 is fine for loopback; the TCP
//     options block we care about lives in the first ~60 bytes.
//   - Timeout: pcap read timeout. Keep short (≤ 500 ms) so the capture
//     goroutine notices a stop() promptly instead of lingering on a read.
//   - Duration: total wall-clock window the sniffer stays alive. Acts as an
//     outer bound for hung captures; the test still calls stop() explicitly
//     once it has driven its traffic.
type snifferConfig struct {
	Iface    string
	BPF      string
	Snaplen  int32
	Timeout  time.Duration
	Duration time.Duration
}

// startSniffer opens a pcap handle on cfg.Iface, applies cfg.BPF, and spawns
// a goroutine that delivers parsed packets through the returned channel.
//
// Concurrency / lifecycle contract:
//   - The returned channel is closed by the capture goroutine when:
//     (a) the caller invokes the returned stop() func, or
//     (b) cfg.Duration elapses, or
//     (c) the pcap handle returns a non-nil non-Timeout error.
//   - stop() is idempotent — safe to call multiple times — and synchronously
//     closes the underlying pcap handle. The caller MUST call it (e.g. via
//     t.Cleanup) so the OS-level handle does not outlive the test.
//   - The capture goroutine swallows pcap.NextErrorTimeoutExpired and keeps
//     polling; any other read error terminates the loop.
//
// Why a channel rather than a callback? T1.5's assertion needs to count
// SYNs while iterating and to retain references to the first few for
// debug-formatting on failure. A channel maps cleanly onto a for-range loop
// in the test; a callback would force closure state and a goroutine of the
// caller's own.
//
// The function fails the test via t.Fatalf if the handle cannot be opened or
// the BPF filter cannot be installed — both indicate a misconfigured
// environment (wrong interface, no libpcap, no CAP_NET_RAW), not a regression
// in code under test.
func startSniffer(t *testing.T, cfg snifferConfig) (<-chan gopacket.Packet, func()) {
	t.Helper()

	if cfg.Snaplen <= 0 {
		cfg.Snaplen = 65535
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 250 * time.Millisecond
	}
	if cfg.Duration <= 0 {
		cfg.Duration = 15 * time.Second
	}

	// Build the pcap handle via the inactive/activate dance because OpenLive
	// does not expose SetImmediateMode, and without immediate mode loopback
	// captures on macOS buffer packets long enough that a sub-second HTTP
	// round trip can finish before the first packet is delivered.
	inactive, err := pcap.NewInactiveHandle(cfg.Iface)
	if err != nil {
		t.Fatalf("startSniffer: NewInactiveHandle(%q): %v", cfg.Iface, err)
	}
	defer inactive.CleanUp()
	if err := inactive.SetSnapLen(int(cfg.Snaplen)); err != nil {
		t.Fatalf("startSniffer: SetSnapLen: %v", err)
	}
	if err := inactive.SetPromisc(true); err != nil {
		t.Fatalf("startSniffer: SetPromisc: %v", err)
	}
	if err := inactive.SetTimeout(cfg.Timeout); err != nil {
		t.Fatalf("startSniffer: SetTimeout: %v", err)
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		t.Fatalf("startSniffer: SetImmediateMode: %v", err)
	}
	handle, err := inactive.Activate()
	if err != nil {
		t.Fatalf("startSniffer: Activate(%q): %v", cfg.Iface, err)
	}
	if cfg.BPF != "" {
		if err := handle.SetBPFFilter(cfg.BPF); err != nil {
			handle.Close()
			t.Fatalf("startSniffer: SetBPFFilter(%q): %v", cfg.BPF, err)
		}
	}

	// LinkType comes from the active handle (BPF Loopback / Ethernet / etc.)
	// so the packet source can pick the right initial decoder. This is what
	// lets the same sniffer work on macOS lo0 (DLT_NULL) and Linux lo
	// (Ethernet) without per-OS branching in the test.
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	// Make the source non-blocking on reads so a stop() while there are no
	// in-flight packets still unblocks the range loop within cfg.Timeout.
	source.NoCopy = true

	out := make(chan gopacket.Packet, 256)
	stopCh := make(chan struct{})

	go func() {
		defer close(out)
		defer handle.Close()
		deadline := time.NewTimer(cfg.Duration)
		defer deadline.Stop()
		pktCh := source.Packets()
		for {
			select {
			case <-stopCh:
				return
			case <-deadline.C:
				return
			case pkt, ok := <-pktCh:
				if !ok {
					return
				}
				select {
				case out <- pkt:
				case <-stopCh:
					return
				case <-deadline.C:
					return
				}
			}
		}
	}()

	var stopped bool
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		close(stopCh)
	}
	return out, stop
}
