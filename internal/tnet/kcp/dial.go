package kcp

import (
	"ctun/internal/conf"
	"ctun/internal/flog"
	"ctun/internal/tnet"
	"ctun/internal/transport"
	"fmt"
	"net"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Dial opens a KCP connection over the supplied transport.Transport. The
// transport must implement transport.PacketConnProvider because KCP (an
// upstream library predating the Transport interface) requires a
// net.PacketConn; this is the documented contract of the syn-tfo transport
// and any future drop-in replacement.
func Dial(addr *net.UDPAddr, cfg *conf.KCP, tr transport.Transport) (tnet.Conn, error) {
	pConn, err := packetConnOf(tr)
	if err != nil {
		return nil, err
	}

	conn, err := kcp.NewConn(addr.String(), cfg.Block, cfg.Dshard, cfg.Pshard, pConn)
	if err != nil {
		return nil, fmt.Errorf("connection attempt failed: %v", err)
	}
	aplConf(conn, cfg)
	flog.Debugf("KCP connection created, creating smux session")

	sess, err := smux.Client(conn, smuxConf(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to create smux session: %w", err)
	}

	flog.Debugf("smux session created successfully")
	return &Conn{tr, conn, sess}, nil
}

// packetConnOf extracts a net.PacketConn from a Transport via the
// PacketConnProvider capability. A transport that does not implement it
// cannot drive KCP and is rejected with a clear error.
func packetConnOf(tr transport.Transport) (net.PacketConn, error) {
	p, ok := tr.(transport.PacketConnProvider)
	if !ok {
		return nil, fmt.Errorf("transport %T does not provide a net.PacketConn (PacketConnProvider not implemented)", tr)
	}
	return p.PacketConn(), nil
}
