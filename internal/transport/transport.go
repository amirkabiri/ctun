// Package transport defines the pluggable Transport interface that ctun uses
// to send and receive raw datagrams, plus a process-wide registry so that
// transport implementations can self-register from their own init() and the
// upper layers can construct one by name.
//
// The interface signature is the canonical one from design-doc.md §7.1.
// Implementations live in sub-packages (currently only internal/transport/syntfo).
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"ctun/internal/conf"
)

// ErrUnknownTransport is returned by New when the requested transport name has
// not been Register'd. Callers may branch on this typed error.
var ErrUnknownTransport = errors.New("unknown transport")

// Datagram is a single unit of data the Transport ferries in either direction.
// SrcAddr is meaningful on Recv (the remote that sent the packet); DstAddr is
// meaningful on Send (where the packet should go).
type Datagram struct {
	Data    []byte
	SrcAddr netip.AddrPort
	DstAddr netip.AddrPort
}

// Transport is the abstract packet I/O layer. Every concrete transport (SYN-TFO
// today, SYN-ACK/UDP/raw IP in the future) implements this exact shape so the
// security and reliability layers above are transport-agnostic.
type Transport interface {
	Send(ctx context.Context, d *Datagram) error
	Recv(ctx context.Context) (*Datagram, error)
	LocalAddr() netip.AddrPort
	Close() error
}

// PacketConnProvider is implemented by transports that have a net.PacketConn
// under the hood and are willing to expose it to consumers that need the
// net.PacketConn shape directly (KCP today). It is a *capability* interface,
// not part of the core Transport contract: future transports may legitimately
// have no backing net.PacketConn at all, and the upper layers are expected to
// migrate to Send/Recv as Phase 1+ progresses.
//
// The return is typed as `any` so this package does not need a hard dependency
// on net.PacketConn just to declare the capability; concrete transports return
// a value that callers type-assert to net.PacketConn. (Phase 1 cuts this
// indirection short and returns net.PacketConn directly because every shipped
// transport supports it.)
type PacketConnProvider interface {
	PacketConn() net.PacketConn
}

// Factory constructs a Transport for the given Config. Factories are registered
// at init() time from each transport sub-package.
type Factory func(cfg Config) (Transport, error)

// Config carries the parameters every Transport needs at construction. The
// ctun-specific network configuration is reachable via Network; ExtraParams is
// reserved for transport-specific knobs that should not be promoted to the
// shared config schema.
type Config struct {
	// Ctx is the parent context. Transports should derive their internal
	// lifetime from this; cancelling it must cause Recv to return.
	Ctx context.Context

	// Network is the ctun network configuration (interface, addresses, pcap
	// buffer sizes, TCP flag profile, ...). Transports typically use this to
	// open their underlying pcap/raw-socket handles.
	Network *conf.Network

	// ExtraParams is a free-form bag for transport-specific knobs. Keys are
	// transport-defined; unknown keys are ignored.
	ExtraParams map[string]any
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds factory under name. It is intended to be called from the
// init() function of a transport sub-package; double-registration of the same
// name panics because that is always a programming error (two transports
// fighting for the same identifier).
func Register(name string, factory Factory) {
	if name == "" {
		panic("transport: Register called with empty name")
	}
	if factory == nil {
		panic("transport: Register called with nil factory for " + name)
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("transport: Register called twice for name " + name)
	}
	registry[name] = factory
}

// New constructs a Transport by registered name. It returns ErrUnknownTransport
// (wrapped with the requested name for log readability) when the name is not
// in the registry.
func New(name string, cfg Config) (Transport, error) {
	registryMu.RLock()
	f, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTransport, name)
	}
	return f(cfg)
}

// Names returns the sorted list of currently-registered transport names. It is
// used by the (future) `ctun transports` subcommand and by tests; callers
// outside those use cases should usually call New instead.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	// Sort for deterministic output. Keep the import minimal: we sort inline
	// with a tiny insertion sort to avoid pulling in "sort" purely for this.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names
}

// reset clears the registry. It exists for tests in this package only.
func reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = map[string]Factory{}
}
