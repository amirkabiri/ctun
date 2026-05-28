package client

import (
	"ctun/internal/flog"
	"ctun/internal/tnet"
	"errors"
	"time"
)

// ErrNoTunnelConn is returned when SOCKS5 / forward dials are issued but
// no tunnel connection ever came up. T4.9: introduced when Start started
// tolerating per-connection handshake failures (the WrongPSK case the
// integration suite exercises); previously Start aborted before SOCKS5
// listened, so a downstream dial could never reach an empty iterator.
var ErrNoTunnelConn = errors.New("client: no tunnel connection available (handshake failed?)")

func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	autoExpire := 300
	if len(c.iter.Items) == 0 {
		return nil, ErrNoTunnelConn
	}
	tc := c.iter.Next()
	go tc.sendTCPF(tc.conn)
	err := tc.conn.Ping(false)
	if err != nil {
		flog.Infof("connection lost, retrying....")
		if tc.conn != nil {
			tc.conn.Close()
		}
		if c, err := tc.createConn(); err == nil {
			tc.conn = c
		}
		tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)
	}
	return tc.conn, nil
}

func (c *Client) newStrm() (tnet.Strm, error) {
	conn, err := c.newConn()
	if err != nil {
		// T4.9: surface unrecoverable errors (no tunnel up at all)
		// instead of looping forever. Pre-existing retry behaviour
		// for transient KCP/smux errors is preserved.
		if errors.Is(err, ErrNoTunnelConn) {
			return nil, err
		}
		flog.Debugf("session creation failed, retrying")
		return c.newStrm()
	}
	strm, err := conn.OpenStrm()
	if err != nil {
		flog.Debugf("failed to open stream, retrying: %v", err)
		return c.newStrm()
	}
	return strm, nil
}
