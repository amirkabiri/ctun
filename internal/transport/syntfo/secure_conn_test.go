// Unit tests for the T3.4 secureConn — the AEAD-wrapping net.PacketConn that
// fronts the raw socket.PacketConn with seal/open + anti-replay.
//
// These tests do NOT spin up pcap. They wire a pair of secureConns through
// an in-memory pipe-style net.PacketConn so the round-trip exercises the
// full plaintext → marshal → seal → wire → open → unmarshal → replay-check
// path with deterministic timing. The pipe conn is defined inline because
// none of the existing transport-level packages provide one.

package syntfo

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ctun/internal/crypto"
	"ctun/internal/protocol"
	"ctun/internal/session"
)

// pipeConn is a tiny in-memory net.PacketConn implementation used to wire
// two secureConns back-to-back. It does not aim to be a faithful UDP socket
// — only the methods secureConn calls (ReadFrom, WriteTo, Close, deadlines,
// LocalAddr) need to work.
//
// A pair of pipeConns share a single inbox per endpoint. WriteTo on one
// endpoint pushes a copy of the bytes (plus the destination addr) onto the
// peer's inbox channel; ReadFrom on the peer pops from its inbox and returns
// the bytes and the recorded sender.
type pipeConn struct {
	local net.Addr
	inbox chan pipePacket
	peer  *pipeConn

	closeOnce sync.Once
	closed    chan struct{}

	readDeadline atomic.Value // time.Time

	// dropNext, when > 0, causes WriteTo to silently drop that many packets
	// instead of pushing them to the peer's inbox. Used to simulate
	// gate-level drops without spinning up pcap.
	dropNext atomic.Int64
}

type pipePacket struct {
	data []byte
	from net.Addr
}

func newPipePair(addrA, addrB string) (*pipeConn, *pipeConn) {
	a := &pipeConn{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1},
		inbox:  make(chan pipePacket, 128),
		closed: make(chan struct{}),
	}
	b := &pipeConn{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2},
		inbox:  make(chan pipePacket, 128),
		closed: make(chan struct{}),
	}
	if addrA != "" {
		a.local = mustResolveUDP(addrA)
	}
	if addrB != "" {
		b.local = mustResolveUDP(addrB)
	}
	a.peer = b
	b.peer = a
	return a, b
}

func mustResolveUDP(s string) net.Addr {
	ua, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(err)
	}
	return ua
}

func (p *pipeConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	var deadlineC <-chan time.Time
	if d, ok := p.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadlineC = timer.C
	}
	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case <-deadlineC:
		return 0, nil, errDeadlineExceeded
	case pkt := <-p.inbox:
		n := copy(buf, pkt.data)
		return n, pkt.from, nil
	}
}

var errDeadlineExceeded = errors.New("pipe: deadline exceeded")

func (p *pipeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if p.dropNext.Load() > 0 {
		p.dropNext.Add(-1)
		return len(b), nil
	}
	// Copy the bytes so the caller can reuse the buffer.
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case p.peer.inbox <- pipePacket{data: cp, from: p.local}:
		return len(b), nil
	case <-p.closed:
		return 0, net.ErrClosed
	case <-p.peer.closed:
		return 0, net.ErrClosed
	}
}

func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *pipeConn) LocalAddr() net.Addr { return p.local }

func (p *pipeConn) SetDeadline(t time.Time) error {
	p.readDeadline.Store(t)
	return nil
}

func (p *pipeConn) SetReadDeadline(t time.Time) error {
	p.readDeadline.Store(t)
	return nil
}

func (p *pipeConn) SetWriteDeadline(_ time.Time) error { return nil }

// Compile-time assertion that pipeConn satisfies the secureConn underlying
// contract. If the underlyingConn interface drifts, this fails the build
// before any test runs.
var _ underlyingConn = (*pipeConn)(nil)

// testKey constructs a non-trivial encKey/authKey pair used by every test
// in this file. The bytes are deterministic so failures are reproducible.
func testKeyPair() (enc, auth [32]byte) {
	for i := range enc {
		enc[i] = byte(0x10 + i)
		auth[i] = byte(0x20 + i)
	}
	return
}

// buildPair returns two secureConns configured as client / server: the
// client has a bound session on its SessionCookieProvider, the server has
// the same session ID registered in its own manager so post-decrypt lookup
// succeeds.
//
// The returned cleanup function closes both conns and is suitable for
// `defer cleanup()`.
func buildPair(t *testing.T) (clientSC, serverSC *secureConn, clientSess *session.Session, cleanup func()) {
	t.Helper()
	encKey, authKey := testKeyPair()

	mgrServer := session.NewManager(encKey, authKey)
	mgrClient := session.NewManager(encKey, authKey)

	// Server mints a session; the client binds the same ID so the cookie
	// matches end-to-end. Real wiring goes through HELLO/HELLO_ACK; for
	// the unit test we shortcut.
	serverSess := mgrServer.NewSession()
	clientBound := mgrClient.BindSession(serverSess.ID)

	clientPipe, serverPipe := newPipePair("127.0.0.1:51001", "127.0.0.1:51002")

	clientProvider := NewSessionCookieProvider(mgrClient)
	clientProvider.Bind(clientBound)

	clientSC = newSecureConn(clientPipe, mgrClient, NewCounters(), clientProvider)
	serverSC = newSecureConn(serverPipe, mgrServer, NewCounters(), nil)

	cleanup = func() {
		clientSC.Close()
		serverSC.Close()
	}
	return clientSC, serverSC, clientBound, cleanup
}

// TestSecureConn_RoundTrip — plaintext bytes written via client.WriteTo land
// in server.ReadFrom unchanged (after AEAD seal/open and replay-check).
func TestSecureConn_RoundTrip(t *testing.T) {
	client, server, _, cleanup := buildPair(t)
	defer cleanup()

	plaintext := []byte("hello from KCP segment")
	dst := mustResolveUDP("127.0.0.1:51002")
	if _, err := client.WriteTo(plaintext, dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	buf := make([]byte, 65535)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got := string(buf[:n])
	if got != string(plaintext) {
		t.Fatalf("plaintext round-trip mismatch: got %q, want %q", got, plaintext)
	}
	if c := server.counters.DroppedAEADOpenFail(); c != 0 {
		t.Errorf("DroppedAEADOpenFail = %d, want 0", c)
	}
	if c := server.counters.DroppedReplay(); c != 0 {
		t.Errorf("DroppedReplay = %d, want 0", c)
	}
	if c := server.counters.DroppedUnknownSession(); c != 0 {
		t.Errorf("DroppedUnknownSession = %d, want 0", c)
	}
}

// TestSecureConn_TamperedCiphertext_Dropped — flip one byte in the
// ciphertext mid-flight. server.ReadFrom must skip the tampered packet and
// return the next clean one; the AEAD-open-fail counter ticks.
func TestSecureConn_TamperedCiphertext_Dropped(t *testing.T) {
	client, server, _, cleanup := buildPair(t)
	defer cleanup()

	dst := mustResolveUDP("127.0.0.1:51002")

	// Send a packet, then tamper with it by pulling it off the server's
	// inbox, flipping a byte, and re-injecting. The trick: we use the
	// pipeConn's drop-next slot to swallow the original write, then we
	// hand-craft a tampered version through serverPipe.inbox directly.
	//
	// Simpler approach: write twice — first one tampered (we tamper its
	// inbox copy), second one clean. ReadFrom must skip the tampered one
	// and return the clean one.
	if _, err := client.WriteTo([]byte("first-tampered"), dst); err != nil {
		t.Fatalf("WriteTo first: %v", err)
	}

	// Inject the tamper: pull the packet off the server's inbox, flip a
	// byte, push it back. The server.under is the pipeConn we control.
	serverPipe := server.under.(*pipeConn)
	pkt := <-serverPipe.inbox
	if len(pkt.data) > 20 {
		// Flip a byte deep inside the ciphertext region (past the
		// nonce). Flipping the nonce would also fail AEAD; flipping
		// the body is more representative of in-flight tampering.
		pkt.data[20] ^= 0x01
	}
	serverPipe.inbox <- pkt

	// Now send a clean packet that should arrive after the tampered one.
	if _, err := client.WriteTo([]byte("second-clean"), dst); err != nil {
		t.Fatalf("WriteTo second: %v", err)
	}

	buf := make([]byte, 65535)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "second-clean" {
		t.Fatalf("got %q, want %q (tampered packet should have been skipped)", got, "second-clean")
	}
	if c := server.counters.DroppedAEADOpenFail(); c != 1 {
		t.Errorf("DroppedAEADOpenFail = %d, want 1", c)
	}
}

// TestSecureConn_UnknownSessionID_Dropped — craft a frame whose SessionID
// is not registered. After AEAD-open the lookup fails and the packet is
// dropped with DroppedUnknownSession.
func TestSecureConn_UnknownSessionID_Dropped(t *testing.T) {
	encKey, authKey := testKeyPair()
	mgrServer := session.NewManager(encKey, authKey)

	clientPipe, serverPipe := newPipePair("127.0.0.1:51001", "127.0.0.1:51002")
	serverSC := newSecureConn(serverPipe, mgrServer, NewCounters(), nil)
	defer serverSC.Close()
	defer clientPipe.Close()

	// Build a frame addressed to a session ID the server doesn't know.
	bogusID := session.SessionID{0xDE, 0xAD, 0xBE, 0xEF}
	msg := &protocol.Message{
		SessionID: uint32(bogusID[0])<<24 | uint32(bogusID[1])<<16 | uint32(bogusID[2])<<8 | uint32(bogusID[3]),
		Sequence:  1,
		Flags:     protocol.FlagData,
		Payload:   []byte("payload"),
	}
	frame, err := protocol.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	sealed, err := crypto.Seal(encKey, frame)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Inject directly into the server pipe's inbox.
	serverPipe.inbox <- pipePacket{data: sealed, from: clientPipe.local}

	// Inject a follow-up valid packet so ReadFrom has something to return
	// after dropping the bogus one.
	goodSess := mgrServer.NewSession()
	goodMsg := &protocol.Message{
		SessionID: uint32(goodSess.ID[0])<<24 | uint32(goodSess.ID[1])<<16 | uint32(goodSess.ID[2])<<8 | uint32(goodSess.ID[3]),
		Sequence:  1,
		Flags:     protocol.FlagData,
		Payload:   []byte("good-payload"),
	}
	goodFrame, err := protocol.Marshal(goodMsg)
	if err != nil {
		t.Fatalf("Marshal good: %v", err)
	}
	goodSealed, err := crypto.Seal(encKey, goodFrame)
	if err != nil {
		t.Fatalf("Seal good: %v", err)
	}
	serverPipe.inbox <- pipePacket{data: goodSealed, from: clientPipe.local}

	buf := make([]byte, 65535)
	_ = serverSC.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := serverSC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "good-payload" {
		t.Fatalf("got %q, want %q (unknown-session packet should have been skipped)", got, "good-payload")
	}
	if c := serverSC.counters.DroppedUnknownSession(); c != 1 {
		t.Errorf("DroppedUnknownSession = %d, want 1", c)
	}
}

// TestSecureConn_ReplayDropped — re-inject the same sealed bytes twice.
// The second injection is detected by the per-session ReplayFilter and
// DroppedReplay ticks.
func TestSecureConn_ReplayDropped(t *testing.T) {
	client, server, _, cleanup := buildPair(t)
	defer cleanup()

	dst := mustResolveUDP("127.0.0.1:51002")

	// Send one packet, capture its sealed bytes from the server's inbox
	// so we can re-inject it.
	if _, err := client.WriteTo([]byte("replay-me"), dst); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	serverPipe := server.under.(*pipeConn)
	first := <-serverPipe.inbox

	// Re-inject the same sealed bytes twice — once via the inbox so
	// ReadFrom sees it (first observation: accept), then again (second
	// observation: replay).
	serverPipe.inbox <- pipePacket{data: append([]byte(nil), first.data...), from: first.from}
	serverPipe.inbox <- pipePacket{data: append([]byte(nil), first.data...), from: first.from}

	// First read should accept the packet.
	buf := make([]byte, 65535)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "replay-me" {
		t.Fatalf("first ReadFrom: got %q, want %q", got, "replay-me")
	}

	// Second read should skip the replay and time out (no further
	// packets to follow). We expect either a deadline error or the
	// counter to tick. We assert the counter and a deadline error.
	_ = server.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	_, _, err = server.ReadFrom(buf)
	if err == nil {
		t.Fatalf("expected deadline error after replay, got nil")
	}
	if c := server.counters.DroppedReplay(); c != 1 {
		t.Errorf("DroppedReplay = %d, want 1", c)
	}
}

// TestSecureConn_ClientWriteBeforeBind_ReturnsError — WriteTo on a client
// whose SessionCookieProvider has no bound session must return ErrNoSession.
// Falling back to plaintext is forbidden (silent downgrade).
func TestSecureConn_ClientWriteBeforeBind_ReturnsError(t *testing.T) {
	encKey, authKey := testKeyPair()
	mgr := session.NewManager(encKey, authKey)

	clientPipe, _ := newPipePair("127.0.0.1:51001", "127.0.0.1:51002")
	defer clientPipe.Close()
	provider := NewSessionCookieProvider(mgr) // intentionally unbound
	clientSC := newSecureConn(clientPipe, mgr, NewCounters(), provider)
	defer clientSC.Close()

	dst := mustResolveUDP("127.0.0.1:51002")
	_, err := clientSC.WriteTo([]byte("anything"), dst)
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("WriteTo before bind: got %v, want ErrNoSession", err)
	}
}

// TestSecureConn_HELLOPlaintext_PassesThrough — write a hand-crafted
// plaintext HELLO frame directly through the underlying pipe, bypassing
// secureConn's AEAD wrap. ReadFrom on the server side must detect it as a
// plaintext handshake (AEAD Open fails, plaintext parse succeeds with
// FlagHello) and return the bytes to the caller.
func TestSecureConn_HELLOPlaintext_PassesThrough(t *testing.T) {
	encKey, authKey := testKeyPair()
	mgr := session.NewManager(encKey, authKey)

	clientPipe, serverPipe := newPipePair("127.0.0.1:51001", "127.0.0.1:51002")
	serverSC := newSecureConn(serverPipe, mgr, NewCounters(), nil)
	defer serverSC.Close()
	defer clientPipe.Close()

	// Build a plaintext HELLO frame: protocol.Message with Flags=FlagHello
	// and a synthetic HELLO payload. We don't validate the inner HELLO HMAC
	// here — that's the handshake's job. We only assert that the framed
	// bytes survive secureConn's AEAD-first / plaintext-fallback routing.
	helloPayload := make([]byte, session.HelloPayloadSize)
	helloPayload[0] = session.HelloVersion
	helloFrame, err := protocol.Marshal(&protocol.Message{
		Flags:   protocol.FlagHello,
		Payload: helloPayload,
	})
	if err != nil {
		t.Fatalf("Marshal HELLO: %v", err)
	}
	// Push directly onto the server pipe's inbox so secureConn reads it
	// as if it had come from the wire.
	serverPipe.inbox <- pipePacket{data: helloFrame, from: clientPipe.local}

	buf := make([]byte, 65535)
	_ = serverSC.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := serverSC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got := buf[:n]
	if len(got) != len(helloFrame) {
		t.Fatalf("plaintext HELLO bytes length mismatch: got %d, want %d", len(got), len(helloFrame))
	}
	for i := range got {
		if got[i] != helloFrame[i] {
			t.Fatalf("plaintext HELLO bytes differ at offset %d: %x vs %x", i, got[i], helloFrame[i])
		}
	}
	// AEAD-open-fail counter should NOT tick — secureConn recognized this
	// as a plaintext handshake via the flag-driven fallback.
	if c := serverSC.counters.DroppedAEADOpenFail(); c != 0 {
		t.Errorf("DroppedAEADOpenFail = %d, want 0 (plaintext HELLO is the expected path)", c)
	}
}
