package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// stubTransport is a minimal Transport that records the Config it was built
// with so the test can prove the factory received what the registry passed in.
// It also satisfies net.PacketConn so the "passed to upper layers as a
// net.PacketConn-like consumer" half of the DoD has something concrete to bind
// to.
type stubTransport struct {
	name string
	cfg  Config
	addr netip.AddrPort
	sent []*Datagram
}

func (s *stubTransport) Send(_ context.Context, d *Datagram) error {
	s.sent = append(s.sent, d)
	return nil
}

func (s *stubTransport) Recv(ctx context.Context) (*Datagram, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *stubTransport) LocalAddr() netip.AddrPort { return s.addr }
func (s *stubTransport) Close() error              { return nil }

// stubPacketConn is the net.PacketConn flavour of the above; the DoD requires
// that "one [stub transport] can be passed to the upper layers as a
// net.PacketConn-like consumer." We model that as a wrapper rather than
// burdening every Transport with net.PacketConn, because KCP is the only
// consumer that needs the net.PacketConn shape and a tiny adapter is all it
// takes.
type stubPacketConn struct {
	t *stubTransport
}

func (p *stubPacketConn) ReadFrom(_ []byte) (int, net.Addr, error)  { return 0, nil, nil }
func (p *stubPacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) { return 0, nil }
func (p *stubPacketConn) Close() error                              { return p.t.Close() }
func (p *stubPacketConn) LocalAddr() net.Addr                       { return nil }
func (p *stubPacketConn) SetDeadline(_ time.Time) error             { return nil }
func (p *stubPacketConn) SetReadDeadline(_ time.Time) error         { return nil }
func (p *stubPacketConn) SetWriteDeadline(_ time.Time) error        { return nil }
func consumeAsPacketConn(_ net.PacketConn)                          {}

// TestRegistryRoundTrip exercises the full registry contract:
//   - two distinct factories register under distinct names
//   - New retrieves each, and the returned Transport reflects the Config the
//     caller passed in (proving the registry didn't drop or alias it)
//   - an unknown name yields ErrUnknownTransport (errors.Is friendly)
//   - one of the constructed transports adapts trivially to net.PacketConn so
//     the upper-layer (KCP-style) consumer shape is exercised
//
// The registry is global so we reset() it at the start to keep the test
// hermetic regardless of other tests in this package.
func TestRegistryRoundTrip(t *testing.T) {
	reset()
	t.Cleanup(reset)

	factoryA := func(cfg Config) (Transport, error) {
		return &stubTransport{
			name: "alpha",
			cfg:  cfg,
			addr: netip.MustParseAddrPort("127.0.0.1:1111"),
		}, nil
	}
	factoryB := func(cfg Config) (Transport, error) {
		return &stubTransport{
			name: "beta",
			cfg:  cfg,
			addr: netip.MustParseAddrPort("127.0.0.1:2222"),
		}, nil
	}

	Register("alpha", factoryA)
	Register("beta", factoryB)

	// Two stubs are registered; both come back; the registered factories
	// receive a Config they can read.
	wantParams := map[string]any{"probe": "value"}
	cfg := Config{Ctx: context.Background(), ExtraParams: wantParams}

	a, err := New("alpha", cfg)
	if err != nil {
		t.Fatalf("New(alpha): %v", err)
	}
	sa, ok := a.(*stubTransport)
	if !ok {
		t.Fatalf("New(alpha) returned %T, want *stubTransport", a)
	}
	if sa.name != "alpha" {
		t.Fatalf("alpha name = %q", sa.name)
	}
	if got := sa.cfg.ExtraParams["probe"]; got != "value" {
		t.Fatalf("alpha cfg.ExtraParams = %#v, want probe=value", sa.cfg.ExtraParams)
	}
	if sa.LocalAddr().Port() != 1111 {
		t.Fatalf("alpha LocalAddr port = %d, want 1111", sa.LocalAddr().Port())
	}

	b, err := New("beta", cfg)
	if err != nil {
		t.Fatalf("New(beta): %v", err)
	}
	sb := b.(*stubTransport)
	if sb.name != "beta" {
		t.Fatalf("beta name = %q", sb.name)
	}

	// Unknown name → typed error, with the name embedded for log readability.
	_, err = New("does-not-exist", cfg)
	if err == nil {
		t.Fatal("New(does-not-exist) returned nil error")
	}
	if !errors.Is(err, ErrUnknownTransport) {
		t.Fatalf("err = %v, want errors.Is(err, ErrUnknownTransport) to be true", err)
	}

	// Names returns both, sorted, and only the registered set.
	names := Names()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("Names() = %v, want [alpha beta]", names)
	}

	// One of the registered transports is adaptable to net.PacketConn — the
	// upper-layer consumer shape the SYN-TFO transport must satisfy for KCP.
	pc := &stubPacketConn{t: sa}
	consumeAsPacketConn(pc) // compile-time check it implements net.PacketConn
	if err := pc.Close(); err != nil {
		t.Fatalf("packetconn.Close: %v", err)
	}
}

// TestRegisterEmptyNamePanics and TestRegisterDoubleRegistrationPanics pin the
// two programming-error guards. They're cheap and document the contract.
func TestRegisterEmptyNamePanics(t *testing.T) {
	reset()
	t.Cleanup(reset)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register(\"\", ...) did not panic")
		}
	}()
	Register("", func(Config) (Transport, error) { return nil, nil })
}

func TestRegisterDoubleRegistrationPanics(t *testing.T) {
	reset()
	t.Cleanup(reset)
	f := func(Config) (Transport, error) { return &stubTransport{}, nil }
	Register("dup", f)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("second Register(\"dup\", ...) did not panic")
		}
	}()
	Register("dup", f)
}

func TestRegisterNilFactoryPanics(t *testing.T) {
	reset()
	t.Cleanup(reset)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register(name, nil) did not panic")
		}
	}()
	Register("nilf", nil)
}
