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

	"github.com/gopacket/gopacket/layers"

	"ctun/internal/conf"
	"ctun/internal/socket"
	"ctun/internal/transport"
)

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
}

// New is the Factory registered under Name. It opens the underlying pcap-based
// packet conn, installs the SYN-TFO option builder + the T0.3 seq-entropy
// fix on the send path, and returns the wrapped transport.
//
// The CookieProvider used here is the static stub from cookie.go; T3.2 will
// replace it by extending Config / wiring a session manager.
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

	t := &Transport{
		cfg:      cfg.Network,
		conn:     pConn,
		cookies:  NewStaticCookieProvider(DefaultStaticCookie()),
		counters: NewCounters(),
	}

	// Install the T1.2 SYN-option builder: every emitted SYN carries the
	// MSS / SACK-perm / Timestamps / WindowScale block plus the Kind=34 TFO
	// option with the current cookie. The closure captures ctx via the
	// outer function's variable; provider implementations may use it once
	// the static stub is replaced.
	pConn.SetSYNOptionsBuilder(func(tsVal uint32) []layers.TCPOption {
		cookie := t.cookies.Cookie(ctx)
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

// gateOptions is the receive-side option-validation hook installed via
// SetSYNGate. It returns true to accept a packet for the upper layer or
// false to drop it; on drop it increments the appropriate counter.
//
// Cookie validation (the HMAC check against the session-bound provider) is
// deferred to T3.2; T1.3 only enforces option *shape*. The decoded cookie
// value is discarded here — see TODO below. Once T3.2 lands, gateOptions
// will pass the cookie up to the session manager for HMAC validation; for
// now it is decoded-but-unused so the hot-path call shape stays stable
// across the T1.3 → T3.2 transition.
//
// Exposed as a method (rather than an anonymous closure inside New) so
// tests can drive the gate directly without spinning up a pcap handle.
// The method only touches Transport.counters; it is safe for concurrent
// use because the counter implementation is built on atomic.Uint64.
func (t *Transport) gateOptions(options []layers.TCPOption) bool {
	_, status := classifyTFO(options)
	switch status {
	case tfoStatusOK:
		// TODO(T3.2): pass the cookie value up to the session manager for
		// the HMAC validation step. Today we discard it because no
		// consumer exists.
		return true
	case tfoStatusMissing:
		t.counters.incNoTFO()
		return false
	case tfoStatusMalformed:
		t.counters.incMalformedTFO()
		return false
	default:
		// Defensive — classifyTFO only returns the three statuses above.
		// If a future refactor adds a new one, count it as a generic
		// missing rather than panic on the hot path.
		t.counters.incNoTFO()
		return false
	}
}

// Counters returns the SYN-TFO Transport's drop-path counters. The future
// metrics framework (see Cross-Cutting Concerns in
// docs/implementation-doc.md) will scrape these; today only tests read them.
// The returned pointer is stable for the lifetime of the Transport.
func (t *Transport) Counters() *Counters {
	return t.counters
}

// PacketConn returns the underlying net.PacketConn. This is the seam KCP
// (which predates the Transport interface) hooks into; it lives only on the
// concrete syntfo.Transport type and is not part of the design-§7.1 interface.
func (t *Transport) PacketConn() net.PacketConn {
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
