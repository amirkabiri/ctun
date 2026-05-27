package kcp

import (
	"ctun/internal/conf"
	"ctun/internal/tnet"
	"ctun/internal/transport"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type Listener struct {
	transport transport.Transport
	cfg       *conf.KCP
	listener  *kcp.Listener
}

// Listen accepts KCP traffic on the supplied transport. Like Dial, this
// requires the transport to expose a net.PacketConn via
// transport.PacketConnProvider.
func Listen(cfg *conf.KCP, tr transport.Transport) (tnet.Listener, error) {
	pConn, err := packetConnOf(tr)
	if err != nil {
		return nil, err
	}
	l, err := kcp.ServeConn(cfg.Block, cfg.Dshard, cfg.Pshard, pConn)
	if err != nil {
		return nil, err
	}

	return &Listener{transport: tr, cfg: cfg, listener: l}, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
	conn, err := l.listener.AcceptKCP()
	if err != nil {
		return nil, err
	}
	aplConf(conn, l.cfg)
	sess, err := smux.Server(conn, smuxConf(l.cfg))
	if err != nil {
		return nil, err
	}
	return &Conn{nil, conn, sess}, nil
}

func (l *Listener) Close() error {
	if l.listener != nil {
		l.listener.Close()
	}
	if l.transport != nil {
		l.transport.Close()
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
