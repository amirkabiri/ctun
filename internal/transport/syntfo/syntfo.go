// Package syntfo is the "syn-tfo" Transport: ctun's default packet I/O
// implementation, built on top of internal/socket's pcap-based PacketConn.
//
// In Phase 1 (T1.1) this was a thin adapter — no TFO option was on the wire.
// T1.2 introduces the TFO option (Kind=34, 8-byte cookie) on send and fixes
// the SYN sequence-number entropy bug T0.3 routed here. T1.3 will enforce
// the option on receive. The package is the *only* place outside
// internal/socket that should import socket.PacketConn; the rest of the
// codebase goes through transport.New.
//
// Layout:
//   - syntfo.go : this file — transport.Transport adapter + registration.
//   - send.go   : pure SYN option-list builder + sequence-number derivation.
//   - cookie.go : CookieProvider interface + StaticCookieProvider stub.
//
// The send.go and cookie.go files are a deliberate leaf (no internal/socket
// import) so internal/socket can import this package — via the
// SetSYNOptionsBuilder hook — without producing a cycle.
package syntfo

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/gopacket/gopacket/layers"

	"ctun/internal/conf"
	"ctun/internal/protocol"
	"ctun/internal/session"
	"ctun/internal/socket"
	"ctun/internal/transport"
)

// ExtraParamCookieProvider is the transport.Config.ExtraParams key (T1.1's
// escape hatch) used to inject a CookieProvider into New. The plumbing
// choice — ExtraParams vs. adding a typed field to transport.Config — is
// documented at the top of New's body; T3.2 uses ExtraParams to keep the
// public Config schema unchanged.
const ExtraParamCookieProvider = "syntfo.cookie_provider"

// ExtraParamSessionManager is the transport.Config.ExtraParams key for
// passing a *session.Manager. It is provided as a convenience when the
// caller has a manager but has not pre-built a SessionCookieProvider —
// New will wrap the manager with NewSessionCookieProvider on the caller's
// behalf. If both keys are set, ExtraParamCookieProvider wins (the explicit
// provider takes precedence) and the manager is held for future use
// (validator wiring lands in T3.3).
const ExtraParamSessionManager = "syntfo.session_manager"

// Name is the registered identifier for this transport, matching the design
// doc and the value of conf.Conf.TransportImpl when defaulted.
const Name = "syn-tfo"

func init() {
	transport.Register(Name, New)
}

// Transport adapts a *socket.PacketConn to the transport.Transport interface
// from design-doc §7.1.
//
// The upper layer that needs net.PacketConn (KCP today) reaches it via
// PacketConn(); future transports without a net.PacketConn backing will need
// the upper layers to migrate to Send/Recv. That migration is out of scope
// for T1.2.
//
// cookies supplies the TFO cookie stamped on every outgoing SYN. T1.2 ships
// a static stub (DefaultStaticCookie); T3.2 will swap it for a session-bound
// HMAC provider at construction time.
//
// counters owns the drop-path counters bumped by the receive-side gate
// installed in New (T1.3). One Counters per Transport, exposed via
// Transport.Counters(); the eventual metrics framework (see Cross-Cutting
// Concerns in docs/implementation-doc.md) will scrape these.
type Transport struct {
	cfg      *conf.Network
	conn     *socket.PacketConn
	cookies  CookieProvider
	counters *Counters
	// mgr is the session manager that backs the cookie provider's validator
	// half. T3.2 stashes it here so T3.3 can hook ValidateCookie into
	// gateOptions without another constructor-API change. It may be nil when
	// no manager was supplied (tests, the legacy static-cookie path).
	mgr *session.Manager

	// secure is the AEAD-wrapping net.PacketConn that fronts conn when a
	// session manager is wired (T3.4). It is what PacketConn() returns to
	// KCP, so all KCP-level traffic goes through AEAD seal/open and
	// anti-replay transparently. Nil when no manager was supplied —
	// PacketConn() then falls back to the raw socket.PacketConn for legacy
	// / test wiring.
	secure *secureConn

	// helloMu guards helloHandler. The handler is normally installed once
	// at server-side startup and then read on every inbound HELLO frame,
	// so an RWMutex would also work; sync.Mutex is simpler and the install
	// path is rare.
	helloMu      sync.Mutex
	helloHandler HelloHandler
}

// HelloHandler is the per-Transport hook the gate dispatches to when an
// inbound frame is identified as a handshake frame — either HELLO
// (Flags=FlagHello, cookie=zero, client→server) or HELLO_ACK
// (Flags=FlagHelloAck, cookie=zero, server→client). The hook is the
// bridge between the per-packet recv path and the higher-level
// session.RunServerHandshake / RunClientHandshake calls: the handler
// is responsible for discriminating on Flags, validating the bytes,
// minting (server) or binding (client) the session, and either pushing
// HELLO_ACK back (server) or delivering it to the client-side waiter
// (client).
//
// frame is the parsed protocol.Message; the handler reads frame.Payload
// (the HELLO bytes) and the source address from src. The payload slice
// aliases the pcap buffer and MUST NOT be retained past the handler's
// return.
//
// The gate calls the handler synchronously on the recv hot path. The
// handler should be fast — production wiring delegates heavy lifting
// (e.g. waiting for the network) to a worker goroutine spawned inside
// the handler. T3.3 only ships the hook; full server-side wiring lands
// in T3.5.
type HelloHandler func(ctx context.Context, frame *protocol.Message, src net.Addr)

// New is the Factory registered under Name. It opens the underlying pcap-based
// packet conn, installs the SYN-TFO option builder + the T0.3 seq-entropy
// fix on the send path, and returns the wrapped transport.
//
// CookieProvider resolution (T3.2):
//
//  1. If cfg.ExtraParams[ExtraParamCookieProvider] is set and is a
//     CookieProvider, use it directly.
//  2. Else if cfg.ExtraParams[ExtraParamSessionManager] is set and is a
//     *session.Manager, wrap it with NewSessionCookieProvider.
//  3. Else fall back to the T1.2 static stub. This keeps existing tests and
//     any caller that does not yet construct a session manager working
//     unchanged.
//
// The ExtraParams escape hatch (defined in T1.1) is the smaller diff than
// adding a typed field to the shared transport.Config — only this transport
// understands the keys, so promoting them to the shared schema would force
// every future transport to acknowledge them. Documented choice; see the
// Configuration discussion in docs/implementation-doc.md → Appendix C
// (entries from T1.1).
func New(cfg transport.Config) (transport.Transport, error) {
	if cfg.Network == nil {
		return nil, fmt.Errorf("syntfo: Config.Network is required")
	}
	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	pConn, err := socket.New(ctx, cfg.Network)
	if err != nil {
		return nil, fmt.Errorf("syntfo: open packet conn: %w", err)
	}

	cookies, mgr, err := resolveCookieProvider(cfg.ExtraParams)
	if err != nil {
		pConn.Close()
		return nil, err
	}

	t := &Transport{
		cfg:      cfg.Network,
		conn:     pConn,
		cookies:  cookies,
		counters: NewCounters(),
		mgr:      mgr,
	}

	// T3.4: when a session manager (and therefore an encKey) is wired,
	// build the secureConn that fronts the raw socket.PacketConn with the
	// AEAD seal/open + anti-replay layer. PacketConn() will return this
	// secureConn to KCP; bare *socket.PacketConn is returned only when
	// no manager is wired (legacy / test paths).
	if mgr != nil {
		var binding sessionBinding
		// SessionCookieProvider doubles as the secureConn's binding —
		// it already tracks the bound *session.Session for cookie
		// stamping, so we reuse it for the WriteTo path's session
		// lookup. Type-assertion is enough; non-session providers
		// (the StaticCookieProvider used by tests / pre-T3.2 wiring)
		// leave binding nil, which on the server side is fine (server
		// secureConns don't WriteTo in T3.4).
		if scp, ok := cookies.(*SessionCookieProvider); ok {
			binding = scp
		}
		t.secure = newSecureConn(pConn, mgr, t.counters, binding)
	}

	// Install the T1.2 SYN-option builder: every emitted SYN carries the
	// MSS / SACK-perm / Timestamps / WindowScale block plus the Kind=34 TFO
	// option with the current cookie. The closure captures ctx via the
	// outer function's variable; provider implementations may use it once
	// the static stub is replaced.
	//
	// T4.9: the builder is called per outbound packet WITH the dst
	// addr. On the SERVER, the cookie depends on which session the
	// destination belongs to (the server's binding is never bound,
	// so falling back on the client-side path's Cookie() returns
	// zero — fatal for the client's gate). We resolve via the
	// secureConn's per-addr session map, which ReadFrom populates on
	// every accepted AEAD frame. On the CLIENT, the SessionCookieProvider
	// is Bind'd post-handshake and Cookie() returns the right value
	// regardless of dstAddr.
	pConn.SetSYNOptionsBuilder(func(tsVal uint32, dstAddr *net.UDPAddr) []layers.TCPOption {
		cookie := t.cookies.Cookie(ctx)
		// If we have a server-side per-addr session map and the
		// caller-supplied cookie is the zero sentinel (which means
		// "no per-Transport binding has bound a session yet" — the
		// usual case on the server), consult the addr map to find
		// the right session for this destination.
		if dstAddr != nil && t.secure != nil && cookie == ([CookieSize]byte{}) {
			if sess := t.secure.lookupAddrSession(dstAddr); sess != nil {
				cookie = sess.Cookie()
			}
		}
		return BuildSYNOptions(cookie, tsVal)
	})

	// Install the T0.3-routed SYN seq-entropy fix.
	pConn.SetSYNSeqDeriver(SYNSeq)

	// Install the T1.3 receive-side TFO gate. Every parsed inbound packet
	// runs through Transport.gateOptions: well-formed Kind=34 passes;
	// missing or malformed TFO drops with the appropriate counter
	// incremented. No per-packet logging — atomic counters are the entire
	// diagnostic surface for the hot path (DoD).
	pConn.SetSYNGate(t.gateOptions)

	return t, nil
}

// gateOptions is the receive-side validation hook installed via
// SetSYNGate. It returns true to accept a packet for the upper layer or
// false to drop it; on drop it increments the appropriate counter. T3.3
// extended the signature with a payload argument so the gate can inspect
// the inner protocol frame (cookie validation + HELLO routing need the
// SessionID / Flags from the framed payload, not just the TCP options).
//
// Decision tree per design §8.4 (also recorded in the T3.3 brief):
//
//  1. TFO option missing → drop, incNoTFO.
//  2. TFO option malformed → drop, incMalformedTFO.
//  3. Inner protocol payload empty or fails Unmarshal → drop,
//     incMalformedFrame. (No session manager: pass through unchanged
//     for tests / non-syntfo deployments — see step 4.)
//  4. No *session.Manager wired (legacy / test mode) → accept on
//     TFO shape alone. Same behaviour as T1.3 — preserves the existing
//     tests and the static-cookie path's "we trust whoever set us up"
//     posture.
//  5. Cookie is all-zero (HELLO sentinel):
//     - Flags == FlagHello → accept (and dispatch to helloHandler if
//     installed). The HELLO path bypasses session lookup because the
//     session is not yet minted.
//     - Otherwise → drop, incNonHelloZeroCookie. Non-HELLO frames with
//     the zero sentinel are either buggy clients or probes; no
//     legitimate cookie matches the zero value (HMAC outputs are
//     indistinguishable from random, so HMAC=000...0 has cryptographic
//     probability 2^-64 per session).
//  6. Cookie is non-zero → run mgr.ValidateCookie(frame.SessionID, cookie).
//     - Accept on hit (session.Counters.BadCookie does NOT tick on the
//     happy path).
//     - Drop on miss, incBadCookieValidator (and the manager's own
//     BadCookie counter ticks inside ValidateCookie itself). The two
//     counters exist for different audiences: the manager's tells the
//     session-layer story (which validator decided to reject), the
//     syntfo one tells the transport-layer story (the syntfo gate
//     dropped a packet for cookie reasons).
//
// AEAD-on-frame note: T3.3 chooses option (a) — handshake is plaintext
// with HMAC — so the gate can Unmarshal the inner protocol frame
// directly. Data frames will be AEAD-wrapped from T3.4 onwards; when
// that lands this gate will need to either (i) decrypt non-HELLO frames
// before Unmarshal or (ii) defer cookie validation to the post-decrypt
// step. The T3.3 brief explicitly defers anti-replay wiring to T3.4, so
// the AEAD-on-data-frames decision rides with it. For T3.3 the gate's
// data-frame branch trusts the SessionID it reads from a plaintext
// header — which is fine because nothing in T3.3 actually sends a
// non-HELLO frame yet (the upper layer is still the legacy paqet path,
// and it is not yet wired to mint AEAD-wrapped frames).
//
// Exposed as a method (rather than an anonymous closure inside New) so
// tests can drive the gate directly without spinning up a pcap handle.
// The method takes the syntfo Counters via t.counters; it is safe for
// concurrent use because both Counters and session.Counters are built on
// atomic.Uint64.
//
// T4.9: the gate now receives the source address so the HELLO-routing
// branch can hand the registered HelloHandler the real peer addr (the
// T3.3 "src=nil open follow-up" closed in this task). Tests that drive
// the gate directly pass nil — the handler simply ignores src in the
// recordingHandler stub.
func (t *Transport) gateOptions(options []layers.TCPOption, payload []byte, src net.Addr) bool {
	cookie, status := classifyTFO(options)
	switch status {
	case tfoStatusMissing:
		t.counters.incNoTFO()
		return false
	case tfoStatusMalformed:
		t.counters.incMalformedTFO()
		return false
	case tfoStatusOK:
		// fallthrough into the cookie / inner-frame logic below.
	default:
		// Defensive — classifyTFO only returns the three statuses above.
		t.counters.incNoTFO()
		return false
	}

	// If no session manager was wired, preserve T1.3 semantics: accept on
	// TFO shape alone. This keeps the static-cookie / test path working
	// unchanged and is the documented fallback resolveCookieProvider
	// picks when neither ExtraParams key is set.
	if t.mgr == nil {
		return true
	}

	isZeroCookie := cookie == ([CookieSize]byte{})
	if isZeroCookie {
		// Zero-cookie sentinel routes the handshake path. The HELLO /
		// HELLO_ACK payloads are plaintext (handshake frames bypass
		// the AEAD wrapper per design §8.4 and the T3.3 plaintext-
		// handshake decision), so the gate can still parse them
		// directly. Anything else with the zero cookie is either a
		// buggy client or a probe and gets dropped.
		//
		// T4.9 split the zero-cookie branch on Flags:
		//
		//   - FlagHello (client→server): dispatch to the installed
		//     HelloHandler (server-side wiring in T4.9 installs one
		//     that drives session.RunServerHandshake) and signal
		//     drop=false to the upper layer. HELLO bytes never bubble
		//     to KCP — they are a transport-internal control frame.
		//
		//   - FlagHelloAck (server→client): signal drop=true (accept)
		//     so the bytes bubble up via secureConn.ReadFrom's
		//     plaintext-FlagHelloAck fallback to the client's
		//     RunClientHandshake driver. The driver reads directly
		//     from PacketConn() during the handshake (KCP is not yet
		//     dialed), parses the bytes as a HelloAck, and proceeds.
		//
		//     Routing HELLO_ACK to the upper layer (rather than via a
		//     handler stash) is what makes the client-side handshake
		//     work on top of the pcap-driven PacketConn: pcap is
		//     configured BlockForever, so a separate "pump" goroutine
		//     cannot be cancelled mid-read. Driving the read in the
		//     same goroutine as RunClientHandshake's retry loop —
		//     directly via PacketConn() — sidesteps the cancellation
		//     problem because the read is in the goroutine that the
		//     retry schedule already manages.
		//
		// HELLO_ACK cookie=zero rationale: the server emits HELLO_ACK
		// BEFORE the client has bound a session, so the client could
		// not LookupByCookie anything sensible if the server stamped
		// the new session's cookie on the SYN. Sticking with zero is
		// symmetric with HELLO and keeps the gate's routing simple.
		// Documented in docs/implementation-doc.md T4.9.
		if len(payload) == 0 {
			t.counters.incMalformedFrame()
			return false
		}
		msg, err := protocol.Unmarshal(payload)
		if err != nil {
			t.counters.incMalformedFrame()
			return false
		}
		switch msg.Flags {
		case protocol.FlagHello:
			// Dispatch to handler (server-side), drop=false to upper
			// layer.
			t.helloMu.Lock()
			h := t.helloHandler
			t.helloMu.Unlock()
			if h != nil {
				h(context.Background(), msg, src)
			}
			return false
		case protocol.FlagHelloAck:
			// Accept to upper layer (client-side RunClientHandshake
			// reads directly).
			return true
		default:
			t.counters.incNonHelloZeroCookie()
			return false
		}
	}

	// Non-zero cookie path: with AEAD-wrapped data frames (T3.4) the inner
	// SessionID is no longer visible in plaintext, so we cannot
	// ValidateCookie by reading it out of the payload. Instead we look the
	// session up by its cookie — the cookie is HMAC(authKey, sessionID)[:8]
	// and is unique per session with overwhelming probability, so this is
	// a sound pre-decrypt fast-reject (design §8.4: "سرور با چک سریع
	// cookie می‌تواند پکت‌های مهاجم را قبل از decrypt دور بریزد").
	//
	// secureConn.ReadFrom performs the actual AEAD Open + SessionID
	// integrity check (the AEAD tag covers the header, so a forger who
	// happens to know a valid cookie still cannot fake the inner
	// SessionID); the gate's job is to short-circuit obvious garbage
	// before we pay for an AEAD Open call.
	if t.mgr.LookupByCookie(cookie) == nil {
		t.counters.incBadCookieValidator()
		// Mirror the T3.3 dual-counter pattern: bump the manager's
		// BadCookie counter too so observers that watch only the
		// session-layer metrics still see the drop. The manager's
		// ValidateCookie used to do this internally; the gate has
		// taken over the bookkeeping responsibility now that it no
		// longer calls ValidateCookie on the hot path.
		t.mgr.Counters().BadCookie.Add(1)
		return false
	}
	return true
}

// SetHelloHandler installs the per-Transport HELLO dispatcher used by the
// receive-side gate. The server-side cmd wiring (T3.5) registers a handler
// that drives session.RunServerHandshake under a worker goroutine; tests
// register a recording handler. Passing nil clears the handler.
//
// Concurrency: the handler is read by the gate hot path on every inbound
// HELLO frame, so the install path takes the small helloMu mutex; the gate
// takes it too while loading the pointer. The cost is one uncontended
// mutex acquire per HELLO — negligible compared to the Unmarshal call the
// gate already pays.
func (t *Transport) SetHelloHandler(h HelloHandler) {
	t.helloMu.Lock()
	t.helloHandler = h
	t.helloMu.Unlock()
}

// Counters returns the SYN-TFO Transport's drop-path counters. The future
// metrics framework (see Cross-Cutting Concerns in
// docs/implementation-doc.md) will scrape these; today only tests read them.
// The returned pointer is stable for the lifetime of the Transport.
func (t *Transport) Counters() *Counters {
	return t.counters
}

// PacketConn returns the net.PacketConn KCP consumes. When the transport
// was constructed with a session manager (the production path), this is
// the AEAD-wrapping secureConn from T3.4 — KCP sees plaintext bytes and
// has no notion of the AEAD layer underneath. When no manager is wired
// (legacy / test paths), the bare socket.PacketConn is returned so the
// pre-T3.4 plaintext behaviour is preserved.
//
// The seam itself (PacketConn() returning a net.PacketConn) predates the
// Transport interface and lives only on the concrete syntfo.Transport
// type; it is not part of design-§7.1's interface.
func (t *Transport) PacketConn() net.PacketConn {
	if t.secure != nil {
		return t.secure
	}
	return t.conn
}

// SocketConn returns the concrete *socket.PacketConn. It exists for the few
// existing sites (server-side TCP-flag plumbing, the dump command) that call
// methods which are not on net.PacketConn. Avoid using it from new code —
// Send/Recv (or, where unavoidable, PacketConn) is the supported surface.
func (t *Transport) SocketConn() *socket.PacketConn {
	return t.conn
}

// Send implements transport.Transport. It writes one datagram via the
// underlying pcap handle. d.DstAddr is the IP+port of the peer; d.SrcAddr is
// unused on send because the underlying socket fills source fields from its
// own configuration.
//
// ctx is reserved for future cancellation/deadline semantics; the current
// underlying socket uses its own deadline machinery via SetWriteDeadline.
func (t *Transport) Send(_ context.Context, d *transport.Datagram) error {
	if d == nil {
		return fmt.Errorf("syntfo: nil Datagram")
	}
	addr := addrPortToUDPAddr(d.DstAddr)
	_, err := t.conn.WriteTo(d.Data, addr)
	return err
}

// Recv implements transport.Transport. It reads one datagram from the
// underlying pcap handle. The returned Datagram's Data points at a fresh
// buffer owned by Recv's caller; SrcAddr is the peer that sent the packet.
func (t *Transport) Recv(_ context.Context) (*transport.Datagram, error) {
	// Match the size the existing dump command uses; it's a per-call
	// allocation today and stays one for T1.1. Steady-state allocations will
	// be tackled when T1.3 rewrites the receive path.
	buf := make([]byte, 65535)
	n, addr, err := t.conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	src, ok := udpAddrToAddrPort(addr)
	if !ok {
		// netip.AddrPort zero value is fine; the upper layer keys off
		// SrcAddr only for transports that surface peer identity.
		src = netip.AddrPort{}
	}
	return &transport.Datagram{
		Data:    buf[:n],
		SrcAddr: src,
	}, nil
}

// LocalAddr implements transport.Transport. The underlying socket.PacketConn
// returns nil for net.Addr (it has no single canonical local endpoint), so we
// fall back to the configured IPv4 or IPv6 address.
func (t *Transport) LocalAddr() netip.AddrPort {
	if t.cfg == nil {
		return netip.AddrPort{}
	}
	if t.cfg.IPv4.Addr != nil {
		if a, ok := netip.AddrFromSlice(t.cfg.IPv4.Addr.IP.To4()); ok {
			return netip.AddrPortFrom(a, uint16(t.cfg.IPv4.Addr.Port))
		}
	}
	if t.cfg.IPv6.Addr != nil {
		if a, ok := netip.AddrFromSlice(t.cfg.IPv6.Addr.IP.To16()); ok {
			return netip.AddrPortFrom(a, uint16(t.cfg.IPv6.Addr.Port))
		}
	}
	return netip.AddrPort{}
}

// Close implements transport.Transport.
func (t *Transport) Close() error {
	return t.conn.Close()
}

// SessionManager returns the *session.Manager wired in via ExtraParams (or
// nil if none was supplied). T3.3 uses this accessor to reach the manager
// when promoting an inbound HELLO into a registered session — T3.2 does not
// call it itself but exposes it now so the wiring is reachable.
func (t *Transport) SessionManager() *session.Manager {
	return t.mgr
}

// resolveCookieProvider implements New's three-step resolution order for the
// CookieProvider (see New's body for the documented order). Extracted into a
// helper so New itself stays readable; the unit tests in cookie_test.go and
// syntfo_test.go exercise both ExtraParams keys against it via New.
//
// Type assertions are intentionally strict — if a caller passes an
// ExtraParam under one of the recognised keys but with the wrong concrete
// type, that is a programming error and we return it rather than silently
// falling through to the static stub. A silent fallback would hide
// misconfiguration (a non-syntfo deployment looking like it had cookies
// wired up when it actually didn't).
func resolveCookieProvider(params map[string]any) (CookieProvider, *session.Manager, error) {
	var mgr *session.Manager
	if v, ok := params[ExtraParamSessionManager]; ok {
		m, ok := v.(*session.Manager)
		if !ok {
			return nil, nil, fmt.Errorf("syntfo: ExtraParams[%q] is not *session.Manager (got %T)", ExtraParamSessionManager, v)
		}
		mgr = m
	}
	if v, ok := params[ExtraParamCookieProvider]; ok {
		p, ok := v.(CookieProvider)
		if !ok {
			return nil, mgr, fmt.Errorf("syntfo: ExtraParams[%q] is not syntfo.CookieProvider (got %T)", ExtraParamCookieProvider, v)
		}
		return p, mgr, nil
	}
	if mgr != nil {
		return NewSessionCookieProvider(mgr), mgr, nil
	}
	return NewStaticCookieProvider(DefaultStaticCookie()), nil, nil
}

// addrPortToUDPAddr translates a netip.AddrPort into the *net.UDPAddr that the
// underlying socket.PacketConn.WriteTo expects.
func addrPortToUDPAddr(ap netip.AddrPort) *net.UDPAddr {
	ip := ap.Addr()
	// 4in6-encoded v4 addresses must be unwrapped so socket.PacketConn
	// dispatches to the v4 send path (it switches on .To4() != nil).
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return &net.UDPAddr{
		IP:   ip.AsSlice(),
		Port: int(ap.Port()),
	}
}

// udpAddrToAddrPort is the inverse of addrPortToUDPAddr for the receive path.
func udpAddrToAddrPort(a net.Addr) (netip.AddrPort, bool) {
	ua, ok := a.(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return netip.AddrPortFrom(ip, uint16(ua.Port)), true
}
