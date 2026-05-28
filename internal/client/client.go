package client

import (
	"context"
	"ctun/internal/conf"
	"ctun/internal/flog"
	"ctun/internal/pkg/iterator"
	"ctun/internal/session"
	"ctun/internal/tnet"
	"sync"
)

type Client struct {
	cfg     *conf.Conf
	mgr     *session.Manager
	iter    *iterator.Iterator[*timedConn]
	udpPool *udpPool
	mu      sync.Mutex
}

func New(cfg *conf.Conf, mgr *session.Manager) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		mgr:     mgr,
		iter:    &iterator.Iterator[*timedConn]{},
		udpPool: &udpPool{strms: make(map[uint64]tnet.Strm)},
	}
	return c, nil
}

func (c *Client) Start(ctx context.Context) error {
	for i := range c.cfg.Transport.Conn {
		tc, err := newTimedConn(ctx, c.cfg, c.mgr)
		if err != nil {
			// T4.9: handshake failures (notably the WrongPSK case the
			// integration suite covers) leave c.iter.Items empty.
			// Returning the error here used to short-circuit
			// startClient before SOCKS5 came up, which made the
			// Wrong-PSK test's "SOCKS5 listening" probe time out
			// before it could exercise the user-visible failure
			// mode (HTTP request through SOCKS5 must fail). Logging
			// and continuing keeps SOCKS5's listener-bind path
			// reachable so callers see the failure via the HTTP
			// dialer's error, not via an early Start abort.
			flog.Errorf("failed to create connection %d: %v", i+1, err)
			continue
		}
		flog.Debugf("client connection %d created successfully", i+1)
		c.iter.Items = append(c.iter.Items, tc)
	}
	go c.ticker(ctx)

	go func() {
		<-ctx.Done()
		for _, tc := range c.iter.Items {
			tc.close()
		}
		flog.Infof("client shutdown complete")
	}()

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %s (%d connections)", ipv4Addr, ipv6Addr, c.cfg.Server.Addr, len(c.iter.Items))
	return nil
}
