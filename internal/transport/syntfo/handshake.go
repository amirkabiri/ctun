// Production handshake driver wired in T4.9. This file holds the
// syntfo-side glue between the per-packet recv path (Transport.gateOptions
// → HelloHandler) and the higher-level session.RunClientHandshake /
// session.RunServerHandshake calls in package session.
//
// # Why this file (and not session/handshake.go)
//
// session/handshake.go owns the cryptographic primitives (BuildHello,
// ValidateHello, the retry schedule) and a pair of narrow Sender /
// ServerSender interfaces. It deliberately does NOT depend on any
// transport — that is what makes the primitives unit-testable.
//
// The Sender / ServerSender implementations need to (a) call
// Transport.Send, (b) read the destination address (server) or wait on
// the recv path's HELLO_ACK channel (client), so they belong on the
// syntfo side of the boundary. Putting them here keeps the session
// package transport-free.
//
// # Wiring layout
//
//	┌─ client ──────────────────────────────────────────────────┐
//	│ Transport.RunClientHandshake(ctx, peerAddr)               │
//	│   ├── installs HelloHandler that pushes HELLO_ACK frames  │
//	│   │   into ackCh                                          │
//	│   ├── builds clientHandshakeSender{transport,peer,ackCh}  │
//	│   ├── session.RunClientHandshake → returns SessionID      │
//	│   ├── mgr.BindSession(id) + cookieProvider.Bind(sess)     │
//	│   └── uninstalls the handler                              │
//	└───────────────────────────────────────────────────────────┘
//
//	┌─ server ──────────────────────────────────────────────────┐
//	│ Transport.InstallServerHandshakeHandler(ctx)              │
//	│   └── installs HelloHandler that, per inbound HELLO,      │
//	│       spawns a goroutine running                          │
//	│       session.RunServerHandshake with                     │
//	│       serverHandshakeSender{transport, peer}              │
//	└───────────────────────────────────────────────────────────┘
//
// HELLO_ACK choice on the wire: cookie=zero (symmetric with HELLO).
// The server emits HELLO_ACK BEFORE the client has bound a session, so
// the client's gate accepts it via the zero-cookie + FlagHelloAck
// branch. See syntfo.go gateOptions for the routing change. Picking
// cookie=zero over "cookie=<new session's cookie>" was an active
// decision: the client manager would otherwise need to LookupByCookie
// against a cookie it has never registered (the session is bound only
// AFTER HELLO_ACK validates), which is the very thing the handshake is
// in the middle of bootstrapping. Documented in
// docs/implementation-doc.md T4.9.

package syntfo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"ctun/internal/flog"
	"ctun/internal/protocol"
	"ctun/internal/session"
	"ctun/internal/transport"
)

// clientHandshakeSender implements session.Sender by (a) marshalling a
// HELLO into a protocol.Message with Flags=FlagHello, SessionID=0 and
// pushing it via Transport.Send to the configured peer; (b) DIRECTLY
// reading from the Transport's PacketConn for an inbound HELLO_ACK,
// guarded by a per-attempt deadline.
//
// # Why the read is direct (not handler-stash)
//
// pcap is configured with BlockForever (see internal/socket/handle.go),
// so a separate "pump" goroutine that reads the conn during the
// handshake cannot be cancelled mid-read — the only way to unblock
// pcap.ReadPacketData is for a packet to arrive. That makes a clean
// shutdown handoff to KCP impossible if we read in a background
// goroutine. Reading directly in the same goroutine as the retry loop
// (this method) sidesteps the problem: when SendHello returns and we
// proceed to ReadFrom with a deadline, either (a) a packet arrives and
// we process it, or (b) the deadline fires and ReadFrom returns
// ErrDeadlineExceeded, which we map to errAckTimeout so the session-
// layer retry loop advances to the next inter-attempt sleep.
//
// # Why FlagHelloAck bytes bubble up
//
// The gate's zero-cookie + FlagHelloAck branch (syntfo.go gateOptions)
// returns true so secureConn.ReadFrom's plaintext-FlagHelloAck fallback
// hands the bytes to this RecvHelloAck. The gate's zero-cookie +
// FlagHello branch still drops to the HelloHandler (server-side path)
// because no client should ever receive a HELLO frame.
type clientHandshakeSender struct {
	tr   *Transport
	peer netip.AddrPort
}

// SendHello implements session.Sender. Wraps h in a protocol.Message
// with SessionID=0 and Flags=FlagHello, then pushes via Transport.Send
// to the configured peer addr.
func (c *clientHandshakeSender) SendHello(ctx context.Context, h session.Hello) error {
	msg := &protocol.Message{
		SessionID: 0,
		Sequence:  0,
		Flags:     protocol.FlagHello,
		Payload:   h.Marshal(),
	}
	frame, err := protocol.Marshal(msg)
	if err != nil {
		return fmt.Errorf("syntfo: marshal HELLO: %w", err)
	}
	return c.tr.Send(ctx, &transport.Datagram{
		DstAddr: c.peer,
		Data:    frame,
	})
}

// RecvHelloAck implements session.Sender. Reads one packet from the
// underlying PacketConn (with a per-attempt deadline of 200 ms),
// parses it as a plaintext HELLO_ACK frame, and returns the parsed
// HelloAck on success. Any failure (deadline, parse error, wrong
// Flags) returns errAckTimeout so session.RunClientHandshake advances
// to the next retry's inter-attempt sleep — see the package-level
// retry-schedule documentation in session/handshake.go.
//
// 200 ms is short enough that the first attempt times out before the
// 250 ms inter-attempt sleep but long enough that a healthy
// round-trip (microseconds on loopback, single-digit ms on a LAN)
// wins the race.
func (c *clientHandshakeSender) RecvHelloAck(ctx context.Context) (session.HelloAck, error) {
	const perAttemptWait = 200 * time.Millisecond
	pc := c.tr.PacketConn()
	if err := pc.SetReadDeadline(time.Now().Add(perAttemptWait)); err != nil {
		return session.HelloAck{}, err
	}
	defer func() { _ = pc.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return session.HelloAck{}, ctx.Err()
		default:
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			// Deadline-exceeded (and any other error) is mapped to
			// errAckTimeout so the session-layer retry loop sleeps
			// and re-sends.
			return session.HelloAck{}, errAckTimeout
		}
		if n == 0 {
			continue
		}
		// The bytes returned by secureConn.ReadFrom's plaintext-
		// FlagHelloAck branch are the FULL framed protocol.Message
		// (header + payload). Re-parse and validate the Flags before
		// extracting the HelloAck payload.
		msg, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			continue
		}
		if msg.Flags != protocol.FlagHelloAck {
			// Some other plaintext frame bubbled up (shouldn't
			// happen given the gate routing); ignore.
			continue
		}
		ack, err := session.ParseHelloAck(msg.Payload)
		if err != nil {
			continue
		}
		return ack, nil
	}
}

// errAckTimeout is returned by clientHandshakeSender.RecvHelloAck on
// per-attempt timeout / parse failure. session.RunClientHandshake
// treats any non-nil non-ctx error as "this attempt failed, sleep for
// the inter-attempt delay and try again," which is exactly the
// schedule we want.
var errAckTimeout = errors.New("syntfo: handshake recv per-attempt timeout")

// serverHandshakeSender implements session.ServerSender by marshalling
// HELLO_ACK into a protocol.Message with Flags=FlagHelloAck and
// SessionID=<minted session> (the outer envelope carries the ID; the
// AEAD layer is bypassed because the handshake is plaintext per design
// §8.4). The TFO cookie stamped onto the SYN is zero — symmetric with
// HELLO and documented at the top of this file.
type serverHandshakeSender struct {
	tr   *Transport
	peer netip.AddrPort
}

// SendHelloAck implements session.ServerSender. Wraps a in the
// envelope and pushes via Transport.Send to peer.
func (s *serverHandshakeSender) SendHelloAck(ctx context.Context, a session.HelloAck) error {
	msg := &protocol.Message{
		// HELLO_ACK carries the minted SessionID in the outer envelope.
		// The HMAC inside the payload binds the same ID; both ends
		// cross-check via ValidateHelloAck.
		SessionID: sessionIDToUint32BE(a.SessionID),
		Sequence:  0,
		Flags:     protocol.FlagHelloAck,
		Payload:   a.Marshal(),
	}
	frame, err := protocol.Marshal(msg)
	if err != nil {
		return fmt.Errorf("syntfo: marshal HELLO_ACK: %w", err)
	}
	// Outbound HELLO_ACK uses the zero TFO cookie. The cookies provider
	// is consulted by the SendHandle's option builder — until the
	// server's SessionCookieProvider is bound to a session, Cookie()
	// returns zero. The server NEVER binds the provider (it serves
	// many sessions), so its outbound HELLO_ACKs already carry zero.
	return s.tr.Send(ctx, &transport.Datagram{
		DstAddr: s.peer,
		Data:    frame,
	})
}

// sessionIDToUint32BE encodes a [4]byte SessionID as a big-endian
// uint32 — the same encoding the rest of the codebase uses (secureConn
// uses encoding/binary.BigEndian.PutUint32 / Uint32 against the
// envelope's SessionID field). Keeping the helper here avoids an
// unnecessary import-cycle-prone re-export from package protocol.
func sessionIDToUint32BE(id session.SessionID) uint32 {
	return uint32(id[0])<<24 | uint32(id[1])<<16 | uint32(id[2])<<8 | uint32(id[3])
}

// RunClientHandshake drives the client side of the HELLO / HELLO_ACK
// exchange for this Transport. On success it returns the
// server-issued *session.Session (the client-side manager has bound
// the ID, the SessionCookieProvider has been Bind'd, and subsequent
// KCP writes will AEAD-wrap under that session).
//
// peer is the server's tunnel addr. authKey is typically
// mgr.AuthKey() — exposing it as a parameter keeps the function
// testable without a Manager.
//
// Concurrency: RunClientHandshake is single-threaded — it installs and
// then uninstalls the HelloHandler around the session.RunClientHandshake
// call. Calling it concurrently from two goroutines would race on the
// handler; the per-Transport client wiring in internal/client only
// drives it once per tunnel connection.
func (t *Transport) RunClientHandshake(ctx context.Context, peer netip.AddrPort, authKey [32]byte) (*session.Session, error) {
	if t.mgr == nil {
		return nil, fmt.Errorf("syntfo: RunClientHandshake requires a session manager")
	}
	scp, ok := t.cookies.(*SessionCookieProvider)
	if !ok {
		return nil, fmt.Errorf("syntfo: RunClientHandshake requires a SessionCookieProvider (got %T)", t.cookies)
	}

	// No HelloHandler is installed on the client side. The gate routes
	// FlagHelloAck (zero cookie) up to the upper layer (return=true);
	// clientHandshakeSender.RecvHelloAck reads it directly from
	// PacketConn() with a per-attempt deadline.
	sender := &clientHandshakeSender{
		tr:   t,
		peer: peer,
	}
	id, err := session.RunClientHandshake(ctx, sender, authKey)
	if err != nil {
		return nil, fmt.Errorf("client handshake: %w", err)
	}
	flog.Debugf("client handshake complete: sessionID=%x", id)
	sess := t.mgr.BindSession(id)
	scp.Bind(sess)
	return sess, nil
}

// InstallServerHandshakeHandler installs the per-Transport HelloHandler
// that drives session.RunServerHandshake for every inbound HELLO. Each
// HELLO spawns a worker goroutine; the worker validates HMAC + skew,
// mints a session, and pushes HELLO_ACK back via serverHandshakeSender.
// On reject the worker returns silently — counters tick inside
// RunServerHandshake; no log.
//
// ctx is the server's lifetime context. Each worker derives its own
// per-handshake context with a short timeout so a stuck send cannot
// pin a goroutine; the timeout is generous (5 s) because the only
// real-world delay is gopacket's pcap inject path.
//
// Concurrency: the handler is invoked on the recv hot path. It
// returns immediately after spawning the worker so the recv loop is
// never blocked.
func (t *Transport) InstallServerHandshakeHandler(ctx context.Context, authKey [32]byte) error {
	if t.mgr == nil {
		return fmt.Errorf("syntfo: InstallServerHandshakeHandler requires a session manager")
	}
	t.SetHelloHandler(func(_ context.Context, frame *protocol.Message, src net.Addr) {
		if frame.Flags != protocol.FlagHello {
			// Server only handles HELLO — HELLO_ACK going to a server
			// would be a misconfigured deployment, drop silently.
			return
		}
		hello, err := session.ParseHello(frame.Payload)
		if err != nil {
			return
		}
		peer, ok := udpAddrToAddrPort(src)
		if !ok {
			// Without a peer addr we cannot reply — drop.
			return
		}
		// Spawn the actual handshake on its own goroutine so the gate's
		// recv loop is not blocked. RunServerHandshake will mint a
		// session and emit HELLO_ACK; on reject it just bumps a
		// counter and returns nil.
		go func() {
			workerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			sender := &serverHandshakeSender{tr: t, peer: peer}
			_, _ = session.RunServerHandshake(
				workerCtx,
				hello,
				sender,
				t.mgr,
				authKey,
				time.Now(),
				session.ClockSkewTolerance,
			)
		}()
	})
	return nil
}
