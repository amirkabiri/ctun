// Phase-3 end-to-end secure-tunnel test (T3.5). Exercises the full stack:
// SYN-TFO transport (T1.x) + HKDF (T2.1) + ChaCha20-Poly1305 AEAD (T2.2) +
// anti-replay window (T2.3) + binary wire format (T3.1) + session manager
// and HMAC cookies (T3.2) + HELLO/HELLO_ACK handshake (T3.3) + AEAD on the
// data path (T3.4).
//
// # What this file owns
//
//   - Test_SecureTunnel (sudo-gated): boots the ctun binary as server + client
//     with `cipher: chacha20poly1305` and `transport_impl: syn-tfo`, drives
//     an HTTP GET through the SOCKS5 listener, and asserts 200 + body. Skips
//     cleanly without root (same constraint as Test_Smoke_SynTfo).
//
//   - Test_SecureTunnel_WrongPSK_ServerSilent (sudo-gated): boots a server
//     with PSK1 and a client with PSK2, drives an HTTP request, and asserts
//     (a) the client's request fails with a timeout and (b) the captured
//     packet stream shows zero outbound packets from the server's tunnel
//     port — the design-doc §8.4 "silent drop" property.
//
//   - Test_SecureTunnel_WrongPSK_HandshakeFails (in-memory, runs locally):
//     wires a session.Sender pair with mismatched encKeys, runs
//     RunClientHandshake under a tight ctx deadline, asserts it returns
//     ErrHandshakeTimeout / DeadlineExceeded and the server emitted zero
//     HELLO_ACK bytes.
//
//   - Test_SecureTunnel_TamperedCiphertext_DropAndRecover (in-memory, runs
//     locally): wires a pipeConn pair; one frame has a byte flipped in
//     flight; asserts the AEAD-open-fail counter ticks once and the next
//     clean frame round-trips successfully.
//
// The sudo-gated tests give us the "kernel + pcap + KCP" coverage; the
// in-memory tests give us the deterministic, no-privileges coverage that
// also runs on developer laptops and in unit-test CI. The two complement
// each other — see replay_test.go's package doc for the same rationale
// T3.4 used.

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ctun/internal/protocol"
	"ctun/internal/session"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/proxy"
)

// Test_SecureTunnel runs the end-to-end secure tunnel happy path twice in a
// single `go test` invocation. The two iterations share the same binary
// (buildCtunBinary caches) but their own fresh ports, keys, tempdirs, and
// subprocesses — same isolation guarantees as Test_Smoke_SynTfo.
//
// The DoD requires the full sudo-gated run in < 30 s; on a quiet loopback
// each iteration completes in ~1–2 s.
//
// To run locally (requires root):
//
//	sudo go test ./test/integration/ -run 'Test_SecureTunnel$' -v
func Test_SecureTunnel(t *testing.T) {
	skipUnlessRunnable(t)

	bin := buildCtunBinary(t)

	t.Run("first-run", func(t *testing.T) {
		runSecureTunnelRoundTrip(t, bin)
	})
	t.Run("second-run", func(t *testing.T) {
		runSecureTunnelRoundTrip(t, bin)
	})
}

// runSecureTunnelRoundTrip is the per-iteration body for Test_SecureTunnel.
// Mirror of runSynTfoRoundTrip from smoke_syn_tfo_test.go, but rendering
// the T3.5 fixtures (which add `cipher: chacha20poly1305` at the top level).
func runSecureTunnelRoundTrip(t *testing.T, ctunBin string) {
	t.Helper()

	tunnelPort, socksPort := allocLoopbackPorts(t)
	iface := lookupTestIface()
	sharedKey := newSharedKey(t)

	const expectedBody = "ctun-secure-ok"
	httpAddr := startTestHTTPServer(t, expectedBody)

	scratch := t.TempDir()
	serverCfg := renderFixture(t, "server-secure.yaml", filepath.Join(scratch, "server.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})
	clientCfg := renderFixture(t, "client-secure.yaml", filepath.Join(scratch, "client.yaml"), fixtureParams{
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
		t.Fatalf("unexpected body via secure tunnel: got %q want %q", got, expectedBody)
	}
}

// Test_SecureTunnel_WrongPSK_ServerSilent boots a server with PSK1 and a
// client with PSK2. The handshake HMAC on the client's HELLO does not
// validate under the server's authKey, so RunServerHandshake silently drops
// every HELLO retry — design-doc §8.4 "silent drop → server remains
// invisible". The client times out after the 5-retry budget (~7.75 s).
//
// Assertions:
//
//   - The HTTP request fails within ~20 s (handshake never completes; KCP
//     can't dial). The 20 s bound is longer than the handshake retry budget
//     but shorter than the test's overall 30 s budget.
//   - A pcap sniff over the failure window observes zero outbound packets
//     from the server's tunnel port. Outbound = source port equals the
//     tunnel port (the server is listening there). Any reply by the server
//     would carry that source port; the DoD says the count must be 0.
//
// Sudo-gated for the same reason as Test_Smoke_SynTfo — pcap on loopback
// needs root, and the ctun binary itself opens raw sockets.
func Test_SecureTunnel_WrongPSK_ServerSilent(t *testing.T) {
	skipUnlessRunnable(t)

	bin := buildCtunBinary(t)

	tunnelPort, socksPort := allocLoopbackPorts(t)
	iface := lookupTestIface()

	const expectedBody = "should-never-be-served"
	httpAddr := startTestHTTPServer(t, expectedBody)

	scratch := t.TempDir()
	serverCfg := renderFixture(t, "server-secure.yaml", filepath.Join(scratch, "server.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  newSharedKey(t), // PSK1
	})
	clientCfg := renderFixture(t, "client-secure.yaml", filepath.Join(scratch, "client.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  newSharedKey(t), // PSK2 — distinct from server's
	})

	serverLog := startCtun(t, bin, serverCfg, "server")
	waitFor(t, fmt.Sprintf("server listening on :%d", tunnelPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", tunnelPort)
	}, serverLog)

	bpf := fmt.Sprintf("tcp and port %d", tunnelPort)
	packets, stopSniffer := startSniffer(t, snifferConfig{
		Iface:    iface,
		BPF:      bpf,
		Snaplen:  65535,
		Timeout:  250 * time.Millisecond,
		Duration: 20 * time.Second,
	})
	t.Cleanup(stopSniffer)

	clientLog := startCtun(t, bin, clientCfg, "client")
	waitFor(t, fmt.Sprintf("SOCKS5 listening on :%d", socksPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", socksPort)
	}, clientLog)

	// Drive the HTTP request in a goroutine so we can bound the wait
	// explicitly. The SOCKS5 GET blocks until the underlying handshake-
	// driven dial fails or the per-request http.Client timeout (15 s)
	// fires — whichever comes first.
	errCh := make(chan error, 1)
	go func() {
		errCh <- attemptHTTPThroughSOCKS5(fmt.Sprintf("127.0.0.1:%d", socksPort), "http://"+httpAddr+"/baseline")
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected HTTP request to fail due to PSK mismatch; got nil")
		}
		t.Logf("expected client failure: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatalf("HTTP request did not time out within bound; client may have wrongly succeeded")
	}

	stopSniffer()
	assertServerSilent(t, packets, tunnelPort)
}

// attemptHTTPThroughSOCKS5 is the non-fatal variant of doHTTPThroughSOCKS5:
// it returns the error so the wrong-PSK test (which expects failure) can
// inspect it without falling through to t.Fatalf. The happy-path tests
// continue to use doHTTPThroughSOCKS5 for its built-in assertions.
func attemptHTTPThroughSOCKS5(socksAddr, target string) error {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("build SOCKS5 dialer: %w", err)
	}
	transport := &http.Transport{
		Dial:                  dialer.Dial,
		ResponseHeaderTimeout: 8 * time.Second,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	return nil
}

// assertServerSilent fails the test if any captured packet had a source
// port equal to tunnelPort — i.e. the server emitted something. The
// design-doc §8.4 "silent drop" property says the server emits nothing
// when the handshake fails.
//
// The captured stream is a mix of client→server SYNs and any server→client
// packets; only the latter (source port == tunnel port) are what the
// silent-drop assertion is about. The client's repeated HELLO retries
// produce a non-zero count of inbound SYNs — that's healthy and expected.
func assertServerSilent(t *testing.T, packets <-chan gopacket.Packet, tunnelPort int) {
	t.Helper()
	clientToServer := 0
	serverToClient := 0
	var firstServerToClientOpts []layers.TCPOption
	for pkt := range packets {
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)
		switch {
		case int(tcp.DstPort) == tunnelPort:
			clientToServer++
		case int(tcp.SrcPort) == tunnelPort:
			serverToClient++
			if firstServerToClientOpts == nil {
				firstServerToClientOpts = append([]layers.TCPOption(nil), tcp.Options...)
			}
		}
	}
	if serverToClient != 0 {
		t.Fatalf(
			"wrong-PSK: server emitted %d packets (must be 0). client→server=%d. first server→client TCP options: %v",
			serverToClient, clientToServer, firstServerToClientOpts,
		)
	}
	t.Logf("wrong-PSK: server stayed silent (0 outbound packets); observed %d client→server SYNs", clientToServer)
}

// ---------------------------------------------------------------------------
// In-memory variants — run locally without sudo. These exercise the security
// properties contracted by the DoD without the pcap/loopback layer. They are
// the canonical T3.5 coverage on developer laptops and in non-root CI.
// ---------------------------------------------------------------------------

// Test_SecureTunnel_WrongPSK_HandshakeFails exercises the "wrong PSK" case
// without spinning up subprocesses. Mismatched authKeys between the client's
// session.Sender and the server's RunServerHandshake mean every HELLO is
// silently dropped on the server side and RunClientHandshake exhausts its
// ctx.
//
// Assertions:
//
//  1. RunClientHandshake returns ErrHandshakeTimeout or context.DeadlineExceeded
//     (depending on whether the ctx fires first or the retry budget does).
//  2. The server emitted zero HELLO_ACK bytes — the silent-drop property.
//
// Bounded to < 1 s wall time via a tight ctx; the test's overall budget is
// well under the 5 s the brief allots in-memory variants.
//
// Runs without sudo; only gated on testing.Short, like replay_test.go.
func Test_SecureTunnel_WrongPSK_HandshakeFails(t *testing.T) {
	if testing.Short() {
		t.Skip("secure-tunnel in-memory test skipped in -short mode")
	}

	// Distinct PSKs → distinct authKeys → no HELLO HMAC the server
	// validates. encKey is irrelevant here (the handshake is plaintext
	// per the T3.3 deviation note) but we pass a server encKey for the
	// session.Manager constructor.
	encServer, authServer := keyPair(0x10)
	_, authClient := keyPair(0x80) // distinct authKey ⇒ distinct HMAC

	mgrServer := session.NewManager(encServer, authServer)

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	// Single-direction channel: client → server. The server's recv
	// goroutine pulls every HELLO and runs RunServerHandshake; on the
	// expected reject path it does nothing.
	clientToServer := make(chan []byte, 16)

	// emittedBytes counts bytes the server's ServerSender would have
	// pushed to the client. Zero on the silent-drop path.
	var emittedBytes atomic.Int64

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			select {
			case <-ctx.Done():
				return
			case raw := <-clientToServer:
				msg, err := protocol.Unmarshal(raw)
				if err != nil {
					continue
				}
				if msg.Flags != protocol.FlagHello {
					continue
				}
				hello, err := session.ParseHello(msg.Payload)
				if err != nil {
					continue
				}
				_, err = session.RunServerHandshake(
					ctx,
					hello,
					emittingSender{counter: &emittedBytes},
					mgrServer,
					authServer,
					time.Now(),
					session.ClockSkewTolerance,
				)
				_ = err // silent drop on reject is the expected path
			}
		}
	}()

	clientSender := &pipeHandshakeSender{
		ctx:            ctx,
		clientToServer: clientToServer,
	}
	_, err := session.RunClientHandshake(ctx, clientSender, authClient)
	cancel()
	<-serverDone

	if err == nil {
		t.Fatalf("RunClientHandshake unexpectedly succeeded with mismatched PSK")
	}
	if !errors.Is(err, session.ErrHandshakeTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunClientHandshake returned %v; want ErrHandshakeTimeout or DeadlineExceeded", err)
	}
	if got := emittedBytes.Load(); got != 0 {
		t.Fatalf("server emitted %d bytes; want 0 (silent-drop property violated)", got)
	}
	t.Logf("wrong-PSK in-memory: client got %v, sent %d HELLO frame(s); server emitted 0 bytes",
		err, clientSender.sent.Load())
}

// keyPair builds a deterministic 32-byte (enc, auth) pair seeded from b.
// Two calls with distinct seeds yield key arrays that share no bytes.
func keyPair(seed byte) (enc, auth [32]byte) {
	for i := range enc {
		enc[i] = byte(int(seed) + i)
		auth[i] = byte(int(seed) + 0x40 + i)
	}
	return
}

// pipeHandshakeSender is a session.Sender implementation that pushes
// marshalled HELLO frames into a channel and blocks RecvHelloAck on ctx
// (never satisfied — the wrong-PSK server never replies). Counts attempts
// via sent so the test can report how many HELLOs were emitted.
type pipeHandshakeSender struct {
	ctx            context.Context
	clientToServer chan<- []byte
	sent           atomic.Int64
}

func (p *pipeHandshakeSender) SendHello(_ context.Context, h session.Hello) error {
	p.sent.Add(1)
	msg := &protocol.Message{
		SessionID: 0,
		Sequence:  0,
		Flags:     protocol.FlagHello,
		Payload:   h.Marshal(),
	}
	frame, err := protocol.Marshal(msg)
	if err != nil {
		return err
	}
	select {
	case p.clientToServer <- frame:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *pipeHandshakeSender) RecvHelloAck(ctx context.Context) (session.HelloAck, error) {
	// Block until ctx cancels. The wrong-PSK server never sends a
	// HELLO_ACK back — that is the silent-drop property under test.
	<-ctx.Done()
	return session.HelloAck{}, ctx.Err()
}

// emittingSender is a session.ServerSender that counts bytes the server
// emitted via SendHelloAck. The wrong-PSK test asserts the count stays at
// zero — on a successful handshake it would equal HelloAckPayloadSize per
// call.
type emittingSender struct {
	counter *atomic.Int64
}

func (e emittingSender) SendHelloAck(_ context.Context, a session.HelloAck) error {
	e.counter.Add(int64(len(a.Marshal())))
	return nil
}

// Test_SecureTunnel_TamperedCiphertext_DropAndRecover wires two AEAD halves
// through an in-memory pipeConn pair (re-used from replay_test.go), flips a
// byte in one captured frame mid-flight, asserts the recipient drops it and
// the AEAD-open-fail counter ticks, then sends a clean frame and asserts it
// round-trips.
//
// This is the integration-layer counterpart to syntfo's
// TestSecureConn_TamperedCiphertext_Dropped unit test. Both exercise the
// same primitives; this one lives in the integration suite so the T3.5 DoD
// checkbox lands here, where the user-visible behaviour is contracted.
//
// Bounded to < 1 s wall time via the pipe's in-process channels.
//
// Runs without sudo; only gated on testing.Short.
func Test_SecureTunnel_TamperedCiphertext_DropAndRecover(t *testing.T) {
	if testing.Short() {
		t.Skip("secure-tunnel in-memory test skipped in -short mode")
	}

	encKey, authKey := keyPair(0x40)
	mgrServer := session.NewManager(encKey, authKey)
	mgrClient := session.NewManager(encKey, authKey)
	serverSess := mgrServer.NewSession()
	clientSess := mgrClient.BindSession(serverSess.ID)

	clientPipe, serverPipe := newPipePair("127.0.0.1:62001", "127.0.0.1:62002")
	defer clientPipe.Close()
	defer serverPipe.Close()

	var replayCounter, unknownCounter, aeadFailCounter atomic.Uint64

	const tamperedPayload = "tampered-payload"
	const cleanPayload = "clean-recovery-payload"

	// Send the would-be-tampered frame: sealAndSend writes the sealed
	// bytes into the server's inbox via the pipe.
	sealAndSend(t, encKey, clientSess, clientPipe, serverPipe.local, []byte(tamperedPayload))

	// Pull the in-flight frame from the server's inbox, flip a byte
	// past the nonce, push back. This models "byte flipped in flight"
	// — the bit-flip happens between the client's WriteTo and the
	// server's ReadFrom.
	pkt := <-serverPipe.inbox
	if len(pkt.data) <= 20 {
		t.Fatalf("captured packet unexpectedly short (%d bytes)", len(pkt.data))
	}
	pkt.data[20] ^= 0x01
	serverPipe.inbox <- pkt

	// Follow up with a clean frame. Receiver should drop the tampered
	// one (incAEADOpenFail) and accept the clean one.
	sealAndSend(t, encKey, clientSess, clientPipe, serverPipe.local, []byte(cleanPayload))

	// receiveOne (from replay_test.go) returns nil on drop. First call
	// drops the tampered frame; second call returns the clean payload.
	first := receiveOne(t, encKey, mgrServer, serverPipe, &replayCounter, &unknownCounter, &aeadFailCounter)
	if first != nil {
		t.Fatalf("tampered packet was not dropped: got %q", first)
	}
	second := receiveOne(t, encKey, mgrServer, serverPipe, &replayCounter, &unknownCounter, &aeadFailCounter)
	if second == nil {
		t.Fatalf("clean packet was unexpectedly dropped")
	}
	if string(second) != cleanPayload {
		t.Fatalf("clean packet payload mismatch: got %q, want %q", second, cleanPayload)
	}

	if got := aeadFailCounter.Load(); got != 1 {
		t.Errorf("aeadFailCounter = %d, want 1", got)
	}
	if got := replayCounter.Load(); got != 0 {
		t.Errorf("replayCounter = %d, want 0", got)
	}
	if got := unknownCounter.Load(); got != 0 {
		t.Errorf("unknownCounter = %d, want 0", got)
	}
}
