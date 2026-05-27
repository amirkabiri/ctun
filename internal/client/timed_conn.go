package client

import (
	"context"
	"ctun/internal/conf"
	"ctun/internal/protocol"
	"ctun/internal/session"
	"ctun/internal/tnet"
	"ctun/internal/tnet/kcp"
	"ctun/internal/transport"
	"ctun/internal/transport/syntfo"
	"fmt"
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
