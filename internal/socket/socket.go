package socket

import (
	"context"
	"ctun/internal/conf"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	recvHandle, err := NewRecvHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        ctx,
		cancel:     cancel,
	}

	return conn, nil
}

// ReadFrom blocks until a packet is available, the context is cancelled,
// or the read deadline (if any) elapses. The underlying pcap handle is
// configured with a short poll timeout (pcapPollTimeout in handle.go) so
// each individual ReadPacketData call returns within a bounded window;
// this method then loops, suppressing the pcap-timeout pseudo-error and
// re-checking ctx/deadline between iterations. The pre-T4.9 BlockForever
// configuration made the ctx/deadline checks here a one-shot: once the
// inner read entered the kernel, only an arriving packet could release
// it. The new behaviour preserves the on-the-wire semantics (still
// blocking from the caller's POV until a real event) while making
// cancellation observable, which is what lets SIGTERM shut down the
// recv loop and what lets the wrong-PSK handshake abandon on ctx
// timeout.
//
// The recv handle's gate-drop path (returning nil/nil/nil for packets
// the SYN gate rejected) is also looped here, matching the legacy
// behaviour: callers continue to receive only "real" packets or
// terminal errors.
func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	for {
		select {
		case <-c.ctx.Done():
			return 0, nil, c.ctx.Err()
		case <-deadline:
			return 0, nil, os.ErrDeadlineExceeded
		default:
		}

		payload, paddr, rerr := c.recvHandle.Read()
		if rerr != nil {
			// pcap returns NextErrorTimeoutExpired when the poll
			// window elapses with no packet. Loop and re-check
			// ctx/deadline. Any other error is terminal (handle
			// closed, kernel error) — bubble it up.
			if rerr == pcap.NextErrorTimeoutExpired {
				continue
			}
			return 0, nil, rerr
		}
		if payload == nil {
			// Gate dropped the packet (or no app layer); look for
			// the next one.
			continue
		}
		n = copy(data, payload)
		return n, paddr, nil
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	err = c.sendHandle.Write(data, daddr)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) Close() error {
	c.cancel()

	if c.sendHandle != nil {
		go c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		go c.recvHandle.Close()
	}

	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	return nil
	// return &net.UDPAddr{
	// 	IP:   append([]byte(nil), c.cfg.PrimaryAddr().IP...),
	// 	Port: c.cfg.PrimaryAddr().Port,
	// 	Zone: c.cfg.PrimaryAddr().Zone,
	// }
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}

// SetSYNOptionsBuilder forwards to the underlying SendHandle. The SYN-TFO
// transport calls this during its New() to install the option builder that
// stamps the Kind=34 TFO option on every emitted SYN (T1.2).
func (c *PacketConn) SetSYNOptionsBuilder(b SYNOptionsBuilder) {
	c.sendHandle.SetSYNOptionsBuilder(b)
}

// SetSYNSeqDeriver forwards to the underlying SendHandle. See SendHandle's
// SetSYNSeqDeriver — this is the route by which the syntfo transport
// installs the T0.3 entropy fix.
func (c *PacketConn) SetSYNSeqDeriver(d SYNSeqDeriver) {
	c.sendHandle.SetSYNSeqDeriver(d)
}

// SetSYNGate forwards to the underlying RecvHandle. The SYN-TFO transport
// calls this during its New() to install the receive-side option-validation
// gate that rejects packets without a valid Kind=34 TFO option (T1.3).
func (c *PacketConn) SetSYNGate(g SYNGate) {
	c.recvHandle.SetSYNGate(g)
}
