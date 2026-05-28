package socket

import (
	"ctun/internal/conf"
	"fmt"
	"net"
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// SYNGate is the receive-side validation hook installed by a Transport
// implementation that cares about the TCP option layout and/or the inner
// protocol payload. The SYN-TFO transport (internal/transport/syntfo, T1.3)
// installs a gate that rejects any parsed packet whose TCP options do not
// contain a well-formed Kind=34 TFO option, and (T3.3) additionally
// validates the TFO cookie against the session table by peeking into the
// protocol-framed payload.
//
// Signature evolution (T1.3 → T3.3): T1.3 declared the gate as
// `func([]layers.TCPOption) bool` — options only. T3.3 widens it to
// `func([]layers.TCPOption, []byte) bool` so the gate can reach into the
// inner protocol payload (cookie validation + HELLO routing both need
// the SessionID / Flags from the framed payload, not just the TCP options).
// The widening is small and contained — only the SYN-TFO transport
// implements a gate — so we picked option (i) from the T3.3 brief over
// option (ii) (moving the validation out of the gate). See syntfo.go's
// gateOptions for the rationale captured at the call site.
//
// Contract:
//   - The gate is invoked on every successfully-parsed inbound TCP packet,
//     immediately after the TCP layer is extracted and before the
//     application-layer payload is hoisted out for the upper layer.
//     Returning false drops the packet (RecvHandle.Read returns
//     nil/nil/nil, the standard "skip this one" signal the upper layers
//     already understand).
//   - The gate is responsible for its own diagnostic side-effects: hot-path
//     log spam is forbidden by T1.3's DoD, so an implementation should
//     bump an atomic counter on drop, not log per packet.
//   - The gate MUST NOT mutate the options slice or the payload bytes.
//     It runs on the hot path and is allowed zero allocations.
//
// Keeping this as a function-typed hook — rather than importing the syntfo
// package directly — preserves the acyclic dependency: socket -> {nothing
// in internal/transport}, syntfo -> socket. Mirror of the send-side
// SYNOptionsBuilder pattern T1.2 introduced.
type SYNGate func(options []layers.TCPOption, payload []byte) bool

type RecvHandle struct {
	handle *pcap.Handle

	// synGate, when non-nil, gates every parsed inbound packet through the
	// transport-supplied option-validation hook. nil means "accept every
	// well-formed TCP packet that passes the BPF filter" — the legacy
	// pre-T1.3 behaviour kept for tests and non-syntfo callers.
	synGate SYNGate
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &RecvHandle{handle: handle}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}
	// LayerTypeEthernet is the right initial decoder on every platform we
	// support today: Linux lo reports DLT_EN10MB (Ethernet) — verified on
	// Ubuntu 24.04 noble during the T4.8 repro — Linux non-loopback
	// interfaces are obviously Ethernet, macOS lo0 and en* surface as
	// DLT_NULL only when accessed via raw BPF (which we don't), and
	// Windows Npcap presents Ethernet for all interfaces. If a future
	// platform/interface surfaces a non-Ethernet link type, the right
	// fix is to mirror test/integration/pcap_helpers.go's
	// `gopacket.NewPacketSource(handle, handle.LinkType())` pattern here.
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	addr := &net.UDPAddr{}

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, nil, nil
	}
	switch netLayer.LayerType() {
	case layers.LayerTypeIPv4:
		addr.IP = netLayer.(*layers.IPv4).SrcIP
	case layers.LayerTypeIPv6:
		addr.IP = netLayer.(*layers.IPv6).SrcIP
	}

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, nil, nil
	}
	switch trLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp := trLayer.(*layers.TCP)
		addr.Port = int(tcp.SrcPort)
		// Transport-supplied receive-side gate. The SYN-TFO transport
		// installs one that (T1.3) requires a well-formed Kind=34 TFO
		// option and (T3.3) additionally cross-checks the cookie against
		// the session table by inspecting the inner protocol payload.
		// Non-syntfo callers leave synGate nil and the gate is a no-op.
		// The gate runs immediately after TCP parse and before
		// upper-layer hoist, so a malformed TFO or invalid cookie
		// short-circuits before we pay for the dispatch. Dropping a
		// packet is signalled by returning nil/nil/nil — the same channel
		// the existing "no application layer" branch already uses, so
		// the upper layers need no change.
		//
		// tcp.LayerPayload() returns the TCP application bytes (i.e.
		// what the upper layer would otherwise see via
		// appLayer.Payload()). Passing it here lets the gate
		// protocol.Unmarshal the inner frame without re-parsing the
		// packet. The byte slice aliases the original pcap buffer and
		// MUST NOT be retained past the gate's return.
		if h.synGate != nil && !h.synGate(tcp.Options, tcp.LayerPayload()) {
			return nil, nil, nil
		}
	case layers.LayerTypeUDP:
		addr.Port = int(trLayer.(*layers.UDP).SrcPort)
	}

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, nil, nil
	}

	return appLayer.Payload(), addr, nil
}

// SetSYNGate installs the receive-side option-validation hook used in the
// TCP branch of Read. The SYN-TFO transport calls this during its New() to
// install a gate that rejects packets without a valid Kind=34 TFO option
// (T1.3). Passing nil restores the legacy "accept every TCP packet that
// passed the BPF filter" behaviour.
//
// Concurrency: same as SetSYNOptionsBuilder on SendHandle — intended to
// be called once at transport setup, before any Read calls. The pointer
// assignment is word-aligned; goroutines will observe either the old or
// the new hook per call, never a torn pointer. There is intentionally no
// mutex because the use case is "install once at startup," not "swap
// mid-flight."
func (h *RecvHandle) SetSYNGate(g SYNGate) {
	h.synGate = g
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
