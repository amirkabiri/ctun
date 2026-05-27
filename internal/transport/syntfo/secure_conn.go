// Package syntfo's secureConn (T3.4): the AEAD-wrapping net.PacketConn that
// sits between KCP and the pcap-backed underlying packet conn.
//
// # Why this lives here
//
// T3.4 owns wiring AEAD (T2.2) and the anti-replay window (T2.3) into the
// data path. The natural seam is a net.PacketConn wrapper: KCP already consumes
// a net.PacketConn via PacketConnProvider (T1.1), so wrapping the
// socket.PacketConn with a secureConn that implements WriteTo / ReadFrom keeps
// the upper layers transparent. KCP sends plaintext bytes to secureConn.WriteTo
// and reads plaintext bytes from secureConn.ReadFrom; the AEAD seam is invisible
// to it.
//
// # Wire layout for data frames
//
//	┌──────────────────────────────────────────────────────────────┐
//	│ AEAD(encKey,                                                 │
//	│      [SessionID:4][Sequence:8][Flags=FlagData:1]             │
//	│      [Length:2 BE][Payload:N])                               │
//	│                                                              │
//	│ = [Nonce:12][Sealed(Header||Payload):N+15][Tag:16]           │
//	└──────────────────────────────────────────────────────────────┘
//
// Total on-wire size: 28 bytes (AEAD overhead) + 15 bytes (protocol header)
// + len(KCP segment). The 28-byte overhead matches design-doc §8.2.
//
// # HELLO/HELLO_ACK stay plaintext
//
// The handshake (T3.3) is explicitly out of the AEAD path: HELLO/HELLO_ACK
// frames are plaintext-framed protocol.Messages whose HMAC over their preamble
// authenticates them (design §8.4 + the deviation note in handshake.go).
// Writes that carry Flags=FlagHello or Flags=FlagHelloAck go to the wire as-is
// without AEAD wrapping. The receive side detects them by attempting an AEAD
// Open first; if Open fails AND the bytes parse as a plaintext protocol.Message
// with FlagHello / FlagHelloAck, the frame is treated as a handshake.
//
// # Routing choice (cookie-driven vs flag-driven)
//
// The task brief recommends cookie-driven dispatch (the gate sees the cookie
// and routes HELLO vs DATA accordingly). At the secureConn ReadFrom layer the
// cookie is not visible — the underlying socket.PacketConn does not surface the
// TCP options. We therefore use flag-driven detection here: try AEAD Open; on
// failure, fall back to plaintext parse and accept only if the bytes form a
// valid protocol.Message with a handshake flag. This is robust because:
//
//   - The probability that a random AEAD ciphertext (which has 28 bytes of
//     uniform random overhead from the nonce and tag) parses as a valid
//     protocol.Message with a recognised Flags byte AND a matching Length
//     field is on the order of 2^-30 per packet.
//   - The gate has already done the cookie-driven fast-reject before the
//     bytes reach secureConn, so the only frames secureConn ever sees are
//     ones the gate accepted (zero-cookie HELLO candidates or non-zero-cookie
//     packets whose cookie is registered).
//
// The gate-level routing is still cookie-driven (see syntfo.go's gateOptions):
// the gate validates the cookie against the session table without touching
// the AEAD-wrapped payload. The secureConn's flag-driven fallback is a
// supplementary disambiguation at the post-gate layer, not a replacement for
// the gate's cookie work.
//
// # Client-side "no session bound" guard
//
// The client cannot AEAD-wrap a data frame until it has bound the session ID
// the server issued via HELLO_ACK. If KCP calls WriteTo before the client's
// SessionCookieProvider has been Bound (handshake not yet complete), WriteTo
// returns ErrNoSession rather than falling back to plaintext. Falling back
// would emit unencrypted KCP segments on the wire — a silent downgrade we
// MUST avoid.
//
// # Server-side per-addr session map (T3.5)
//
// The server has many concurrent clients and therefore no single bound
// session — the client-side sessionBinding pattern does not apply. Instead,
// the server-side secureConn keeps a per-addr session map: every time
// ReadFrom successfully opens an AEAD frame from some src addr, it records
// (addr → *session.Session) in the map. When KCP later calls WriteTo with
// the same addr (to send the corresponding ACK / data segment back to that
// client), WriteTo looks up the session in the map, stamps its ID and
// NextSeq into the outgoing frame, and AEAD-seals.
//
// This relies on KCP's invariant that the server only writes back to addrs
// it has heard from — which holds for KCP's flow because every server-side
// PacketConn write is in response to an inbound segment KCP just read. The
// HELLO/HELLO_ACK exchange uses the plaintext send path (not secureConn.
// WriteTo), so the bootstrap "no map entry yet" case never reaches WriteTo.
//
// A misbehaving / racing caller that hits WriteTo before any inbound frame
// from addr was processed still gets ErrNoSession; the map is the only safe
// way to know which session's ID and counter to stamp, and inventing one
// would emit a frame the client cannot decrypt.

package syntfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"ctun/internal/crypto"
	"ctun/internal/protocol"
	"ctun/internal/session"
)

// ErrNoSession is returned by secureConn.WriteTo when the caller is the
// client-side, an AEAD wrap would be required, and no session has been bound
// yet (the SessionCookieProvider's Bound() is still nil). Callers should
// either wait for the handshake to complete or treat this as a fatal error.
//
// It is a typed sentinel so callers can branch with errors.Is; the secureConn
// itself never branches on it (it just returns the error and lets the caller
// decide).
var ErrNoSession = errors.New("syntfo: no session bound; handshake not complete")

// ErrSecureConnClosed is returned by ReadFrom / WriteTo when the conn has
// been Closed.
var ErrSecureConnClosed = errors.New("syntfo: secure conn closed")

// sessionBinding is the narrow interface secureConn needs to learn the
// current client-bound session. SessionCookieProvider implements it via
// Bound(); on the server side the binding comes from per-packet inbound
// lookups, so the server-side secureConn does not consult this interface
// for read routing.
//
// Exposed as an interface (rather than a hard *SessionCookieProvider
// dependency) so tests can inject a stub binding without going through the
// full provider machinery.
type sessionBinding interface {
	// Bound returns the currently bound session, or nil if none has been
	// bound yet (pre-handshake).
	Bound() *session.Session
}

// underlyingConn is the subset of net.PacketConn methods secureConn needs
// from the layer it wraps. Declaring it as a local interface (rather than a
// hard *socket.PacketConn dependency) lets tests inject a pipe-style
// in-memory conn without bringing up pcap.
type underlyingConn interface {
	ReadFrom(p []byte) (n int, addr net.Addr, err error)
	WriteTo(p []byte, addr net.Addr) (n int, err error)
	LocalAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	Close() error
}

// secureConn is the net.PacketConn that wraps the underlying socket-level
// PacketConn with the data-path AEAD + anti-replay layer.
//
// # Concurrency
//
// ReadFrom and WriteTo may be called concurrently with each other and with
// themselves. Internal state (sequence counter on the bound session,
// ReplayFilter on receive sessions) is itself concurrent-safe; the secureConn
// holds no additional locks on the hot path. Close is idempotent and uses a
// sync.Once.
type secureConn struct {
	under    underlyingConn
	encKey   [32]byte
	mgr      *session.Manager
	counters *Counters

	// binding is the client-side SessionCookieProvider (or any
	// sessionBinding) used by WriteTo to fetch the bound session for
	// outbound AEAD wrapping. nil on the server side: the server stamps
	// the inbound session's ID/cookie based on the per-addr map below
	// (populated as ReadFrom successfully opens frames).
	binding sessionBinding

	// addrMu guards addrSessions. The map is hot on both the read path
	// (insert on every accepted AEAD frame) and the write path (lookup on
	// every server-side outbound segment), but the operations are short
	// (single map lookup / assign) so a plain RWMutex is appropriate.
	addrMu       sync.RWMutex
	addrSessions map[string]*session.Session

	closeOnce sync.Once
	closed    chan struct{}
}

// newSecureConn constructs a secureConn around under, using the manager's
// encKey for AEAD seal/open and looking up sessions in the manager's table.
//
// binding may be nil on the server side (the server does not maintain a
// single bound session — it serves many). On the client side the
// SessionCookieProvider returned by NewSessionCookieProvider is the
// canonical binding.
func newSecureConn(under underlyingConn, mgr *session.Manager, counters *Counters, binding sessionBinding) *secureConn {
	return &secureConn{
		under:        under,
		encKey:       mgr.EncKey(),
		mgr:          mgr,
		counters:     counters,
		binding:      binding,
		addrSessions: make(map[string]*session.Session),
		closed:       make(chan struct{}),
	}
}

// WriteTo implements net.PacketConn. It treats p as a plaintext KCP segment,
// wraps it in a protocol.Message with Flags=FlagData and a fresh per-session
// sequence number, AEAD-seals the marshalled frame, and writes the sealed
// bytes via the underlying conn.
//
// HELLO/HELLO_ACK frames bypass this path: the handshake code writes its
// pre-marshalled protocol.Message bytes directly via a different sender, so
// WriteTo never has to discriminate between data and handshake here. The
// only caller of WriteTo today is KCP (via the PacketConnProvider seam),
// which only ever sends data segments.
//
// Returns:
//   - ErrNoSession if the client has not yet bound a session.
//   - The wrapped error from the underlying WriteTo on transport-level
//     failure.
//   - ErrSecureConnClosed if Close has been called.
func (s *secureConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-s.closed:
		return 0, ErrSecureConnClosed
	default:
	}

	var sess *session.Session
	if s.binding != nil {
		// Client-side path: a SessionCookieProvider tracks the single
		// bound session.
		sess = s.binding.Bound()
	} else {
		// Server-side path (T3.5): look the destination's session up in
		// the per-addr map populated by ReadFrom. Until the first inbound
		// AEAD frame from addr has been processed there is no entry, in
		// which case we return ErrNoSession rather than guessing.
		sess = s.lookupAddrSession(addr)
	}
	if sess == nil {
		return 0, ErrNoSession
	}

	// Build the protocol.Message. SessionID is the bound session's ID
	// (big-endian uint32 encoding of the [4]byte SessionID); Sequence
	// is the next monotonic value from the per-session counter (starts
	// at 1).
	msg := &protocol.Message{
		SessionID: binary.BigEndian.Uint32(sess.ID[:]),
		Sequence:  sess.NextSeq(),
		Flags:     protocol.FlagData,
		Payload:   p,
	}
	frame, err := protocol.Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("syntfo: marshal data frame: %w", err)
	}
	sealed, err := crypto.Seal(s.encKey, frame)
	if err != nil {
		return 0, fmt.Errorf("syntfo: seal data frame: %w", err)
	}
	if _, err := s.under.WriteTo(sealed, addr); err != nil {
		return 0, err
	}
	// Return the size the caller provided (KCP expects len(p) on success,
	// not the sealed/wrapped size — KCP's bookkeeping is in plaintext
	// segment units).
	return len(p), nil
}

// ReadFrom implements net.PacketConn. It reads one packet from the underlying
// conn and:
//
//  1. Attempts AEAD Open under encKey. On success the opened plaintext is
//     a protocol.Message; we Unmarshal it, look up its SessionID, run the
//     session's ReplayFilter.Check on the Sequence, and on accept return
//     the inner Payload bytes (the KCP segment) to the caller.
//  2. On Open failure, falls back to plaintext parse and treats the frame
//     as a HELLO / HELLO_ACK if it parses cleanly with one of those Flags.
//     The HELLO bytes are returned to the caller (so the handshake code can
//     pick them up); KCP itself ignores frames that don't look like KCP
//     segments, so a stray HELLO bubbling up to KCP is benign — KCP just
//     discards it.
//  3. If both routes fail, drops the frame (returns nil/nil/nil via the
//     "skip" sentinel — same channel the gate uses) and re-loops to read
//     the next packet. The appropriate counter is incremented per the
//     failure mode (AEAD open vs unknown session vs replay).
//
// The retry-on-drop loop lives inside ReadFrom (rather than letting the
// caller observe nil/nil/nil) because net.PacketConn's contract is "block
// until a real packet arrives"; KCP would interpret nil/nil/nil as a zero-
// byte read and behave unpredictably.
func (s *secureConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case <-s.closed:
			return 0, nil, ErrSecureConnClosed
		default:
		}

		// Read into a scratch buffer sized for the maximum possible
		// inbound frame. We can't read directly into p because p is
		// sized for plaintext and the inbound bytes are AEAD-wrapped
		// (larger by 28 bytes plus the 15-byte protocol header).
		buf := make([]byte, 65535)
		n, addr, err := s.under.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n == 0 {
			// Underlying gate dropped this packet (nil/nil/nil "skip"
			// sentinel mapped to a zero-byte read by the layer below).
			// Loop to read the next one.
			continue
		}

		raw := buf[:n]

		// Try AEAD path first.
		opened, err := crypto.Open(s.encKey, raw)
		if err == nil {
			plaintext, sess, ok := s.handleAEADFrame(opened)
			if !ok {
				continue
			}
			// Server-side per-addr binding (T3.5): record the
			// (addr → session) mapping so a subsequent WriteTo to
			// the same addr knows which session's ID and sequence
			// counter to stamp. Client-side has its own binding and
			// does not consult this map. Recording unconditionally
			// is harmless on the client side (its WriteTo never
			// reads the map).
			if addr != nil {
				s.rememberAddrSession(addr, sess)
			}
			copied := copy(p, plaintext)
			return copied, addr, nil
		}

		// AEAD Open failed. The frame might be a plaintext HELLO /
		// HELLO_ACK (those bypass AEAD). Try to parse it as a
		// protocol.Message and accept only if it carries a handshake
		// flag.
		if msg, perr := protocol.Unmarshal(raw); perr == nil {
			if msg.Flags == protocol.FlagHello || msg.Flags == protocol.FlagHelloAck {
				// Return the entire framed handshake bytes (header
				// + payload). The caller (handshake-aware logic) is
				// responsible for re-parsing. KCP, if it sees these,
				// will discard them as malformed KCP segments.
				copied := copy(p, raw)
				return copied, addr, nil
			}
			// Parsed cleanly but the flag is not a handshake. This
			// is unexpected — the gate should have routed only
			// handshake frames through the zero-cookie branch and
			// only AEAD-wrapped frames through the non-zero branch.
			// Treat as malformed and drop.
			s.counters.incMalformedFrame()
			continue
		}

		// Neither AEAD nor plaintext parse worked. Most likely a
		// tampered ciphertext or a stray probe; bump the AEAD-open-fail
		// counter (it's the dominant cause) and drop.
		s.counters.incAEADOpenFail()
		_ = err // suppress unused; the typed branch on errors.Is is left for future logging
	}
}

// handleAEADFrame processes a successfully-opened AEAD payload. It returns
// the inner plaintext payload (the KCP segment), the resolved Session (so the
// caller can register the addr → session mapping), and true on accept; nil
// payload, nil session, and false on drop. Counters are incremented on drop.
func (s *secureConn) handleAEADFrame(opened []byte) ([]byte, *session.Session, bool) {
	msg, err := protocol.Unmarshal(opened)
	if err != nil {
		// The AEAD tag matched but the inner protocol frame is
		// malformed. This is implausible without a corresponding bug
		// in our Marshal step (the AEAD tag covers the marshalled
		// bytes, so a mismatch here means we trusted a payload our
		// peer hand-built). Treat as malformed.
		s.counters.incMalformedFrame()
		return nil, nil, false
	}

	// Look up the session by ID. After a successful Open we trust the
	// SessionID — the AEAD tag covers the full header, so a forger
	// cannot have planted a SessionID that survived AEAD verification.
	var id session.SessionID
	binary.BigEndian.PutUint32(id[:], msg.SessionID)
	sess := s.mgr.LookupSession(id)
	if sess == nil {
		s.counters.incUnknownSession()
		return nil, nil, false
	}

	// Anti-replay: per-session sliding window over recently-observed
	// sequence numbers. Duplicates and too-old sequence numbers drop.
	if !sess.ReplayFilter().Check(msg.Sequence) {
		s.counters.incReplay()
		return nil, nil, false
	}

	return msg.Payload, sess, true
}

// rememberAddrSession records the (addr → session) mapping used by the
// server-side WriteTo path. Called from ReadFrom after a successful AEAD
// Open + session lookup + replay check. Re-binding the same addr (e.g. a
// client that reconnected and was issued a new session) silently overwrites
// the old mapping — the newer session is the one KCP will be replying to.
func (s *secureConn) rememberAddrSession(addr net.Addr, sess *session.Session) {
	key := addr.String()
	s.addrMu.Lock()
	if existing, ok := s.addrSessions[key]; !ok || existing != sess {
		s.addrSessions[key] = sess
	}
	s.addrMu.Unlock()
}

// lookupAddrSession returns the session previously associated with addr via
// rememberAddrSession, or nil if no such mapping exists. Used by the
// server-side WriteTo path.
func (s *secureConn) lookupAddrSession(addr net.Addr) *session.Session {
	if addr == nil {
		return nil
	}
	key := addr.String()
	s.addrMu.RLock()
	sess := s.addrSessions[key]
	s.addrMu.RUnlock()
	return sess
}

// LocalAddr implements net.PacketConn. Delegated to the underlying conn
// because secureConn does not change the network identity.
func (s *secureConn) LocalAddr() net.Addr {
	return s.under.LocalAddr()
}

// SetDeadline implements net.PacketConn. Delegated.
func (s *secureConn) SetDeadline(t time.Time) error {
	return s.under.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn. Delegated.
func (s *secureConn) SetReadDeadline(t time.Time) error {
	return s.under.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn. Delegated.
func (s *secureConn) SetWriteDeadline(t time.Time) error {
	return s.under.SetWriteDeadline(t)
}

// Close implements net.PacketConn. Idempotent.
func (s *secureConn) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.under.Close()
	})
	return err
}
