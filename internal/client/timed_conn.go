package client

import (
	"context"
	"ctun/internal/conf"
	"ctun/internal/flog"
	"ctun/internal/protocol"
	"ctun/internal/session"
	"ctun/internal/tnet"
	"ctun/internal/tnet/kcp"
	"ctun/internal/transport"
	"ctun/internal/transport/syntfo"
	"fmt"
	"net"
	"net/netip"
	"time"
)

type timedConn struct {
	cfg    *conf.Conf
	mgr    *session.Manager
	conn   tnet.Conn
	expire time.Time
	ctx    context.Context
}

func newTimedConn(ctx context.Context, cfg *conf.Conf, mgr *session.Manager) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, mgr: mgr, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.cfg.Network
	// Plumb the session manager through ExtraParams (T1.1's transport-specific
	// escape hatch). The syn-tfo transport recognises the key and wires the
	// SessionCookieProvider so post-handshake packets stamp the right TFO
	// cookie; pre-handshake (HELLO) frames still get the zero sentinel until
	// the client binds the session ID returned by HELLO_ACK in T3.3.
	tr, err := transport.New(tc.cfg.TransportImpl, transport.Config{
		Ctx:     tc.ctx,
		Network: &netCfg,
		ExtraParams: map[string]any{
			syntfo.ExtraParamSessionManager: tc.mgr,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("could not create transport: %w", err)
	}

	// T4.9: drive the HELLO/HELLO_ACK handshake before kcp.Dial.
	// secureConn.WriteTo returns ErrNoSession until the
	// SessionCookieProvider has been Bind'd, so the very first KCP
	// segment after Dial cannot leave the host until the handshake has
	// completed. RunClientHandshake itself enforces the retry schedule
	// (250 ms → 4 s, 5 attempts; total ≤ 7.75 s) and returns
	// ErrHandshakeTimeout on exhaustion. Failures here release the
	// transport — same posture as the kcp.Dial branch below.
	if st, ok := tr.(*syntfo.Transport); ok {
		peerAddr := udpAddrPort(tc.cfg.Server.Addr)
		// Slightly above the handshake's 5-retry / 7.75 s budget so
		// the deadline only fires when the retry schedule has fully
		// elapsed without an ACK. Wrong-PSK and broken-network paths
		// both surface as ErrHandshakeTimeout at this boundary; the
		// integration suite's WrongPSK_ServerSilent test relies on
		// SOCKS5 coming up within 10 s, so anything noticeably above
		// the schedule budget would push the test over its bound.
		hctx, hcancel := context.WithTimeout(tc.ctx, 9*time.Second)
		sess, herr := st.RunClientHandshake(hctx, peerAddr, tc.mgr.AuthKey())
		hcancel()
		if herr != nil {
			tr.Close()
			return nil, fmt.Errorf("handshake failed: %w", herr)
		}
		flog.Debugf("client handshake complete: session bound (id=%x)", sess.ID)
	}

	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, tr)
	if err != nil {
		// Releasing the transport here mirrors the previous behaviour where
		// kcp.Dial's failure left the packet conn owned by us; close it so
		// we don't leak the pcap handle.
		tr.Close()
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}

// udpAddrPort converts a *net.UDPAddr (paqet's config representation of
// the server endpoint) into the netip.AddrPort the syntfo handshake
// driver expects. Returns the netip zero value when the addr is nil
// or unparseable — callers that depend on a non-zero peer will see the
// handshake fail downstream when transport.Send rejects the
// unspecified addr.
func udpAddrPort(addr *net.UDPAddr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return netip.AddrPort{}
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port))
}
