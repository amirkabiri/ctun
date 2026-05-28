package socket

import (
	"ctun/internal/conf"
	"ctun/internal/flog"
	"ctun/internal/pkg/hash"
	"ctun/internal/pkg/iterator"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// zeroMAC is the six-byte all-zero MAC used as the Ethernet SrcMAC when the
// configured interface reports an empty HardwareAddr — the typical case on
// the Linux loopback interface (`lo`), where net.InterfaceByName("lo").
// HardwareAddr is nil/zero-length. gopacket's Ethernet.SerializeTo rejects
// any SrcMAC whose length is not 6 with "invalid src MAC", so without this
// normalisation every WritePacketData on lo would fail at the serialize step
// and KCP would silently swallow the error (see T4.8). lo accepts any source
// MAC anyway because nothing on the wire ever observes it: the loopback
// driver hands the packet back up the stack, not out a physical link.
var zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

// SYNOptionsBuilder produces the TCP option list for an outgoing SYN. The
// SYN-TFO transport (internal/transport/syntfo) installs one via
// SetSYNOptionsBuilder so the option-set (in particular the Kind=34 TFO
// option introduced in T1.2) lives in the transport, not in this low-level
// pcap wrapper. tsVal is the timestamp value the caller wants stamped into
// the Timestamps option.
//
// Keeping this as a function-typed hook — rather than importing the syntfo
// package directly — preserves an acyclic dependency: socket -> {nothing in
// internal/transport}, syntfo -> socket. If a future transport wants a
// different option set it installs its own builder; the default behaviour
// when no builder is installed is the pre-T1.2 paqet option set.
type SYNOptionsBuilder func(tsVal uint32) []layers.TCPOption

// SYNSeqDeriver returns the TCP sequence number for an outgoing SYN. T0.3
// routed the seq-entropy fix to T1.2; we accept a pluggable derivation so
// the transport that owns the wire format (syntfo today) can choose the
// derivation that makes its packets dedup-resistant, while this package
// stays a thin pcap wrapper with no semantic say in TCP sequencing.
type SYNSeqDeriver func(timeBase, counter uint32) uint32

type SendHandle struct {
	handle      *pcap.Handle
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	time        uint32
	tsCounter   uint32
	tcpF        TCPF
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	bufPool     sync.Pool

	// synOptionsBuilder, when non-nil, replaces the default SYN option list.
	// Installed by internal/transport/syntfo at construction time so the TFO
	// option (Kind=34, T1.2) can land on every SYN without socket importing
	// syntfo (which would create a cycle). nil means "use the paqet-era
	// default option set".
	synOptionsBuilder SYNOptionsBuilder

	// synSeqDeriver, when non-nil, replaces the default SYN sequence-number
	// derivation. T0.3 found the default (`1 + counter & 0x7`) only emits 8
	// distinct sequence numbers, which causes silent dedup drops in SYN-only
	// mode; the syntfo transport installs a 32-bit-entropy deriver via this
	// hook. nil keeps the legacy behaviour for transports that don't care.
	synSeqDeriver SYNSeqDeriver

	// writeSerializeErr counts gopacket.SerializeLayers failures inside
	// Write. T4.8: before this counter existed, a SerializeLayers error on
	// the SrcMAC length check was returned up through PacketConn.WriteTo
	// and silently swallowed by KCP, making the failure mode "no packets
	// on the wire" with no diagnostic. The counter ticks per failure; the
	// warnLoggedSerialize flag throttles diagnostic logs to one line for
	// the lifetime of the handle (per the per-packet log-spam ban in the
	// design's Cross-Cutting Concerns).
	writeSerializeErr   atomic.Uint64
	writePcapErr        atomic.Uint64
	warnLoggedSerialize atomic.Bool
	warnLoggedPcap      atomic.Bool
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	// Normalise the source MAC. On the Linux loopback interface
	// net.InterfaceByName("lo").HardwareAddr is nil/zero-length; without
	// this every Ethernet.SerializeTo would fail with "invalid src MAC"
	// (T4.8). zeroMAC is safe on lo because the loopback driver does not
	// transmit the frame on any physical link — only the L3+ payload is
	// re-delivered to the local stack. For non-loopback interfaces with
	// a real hardware address we keep that address unchanged so packets
	// emitted on physical NICs continue to carry the correct source MAC.
	srcMAC := cfg.Interface.HardwareAddr
	if len(srcMAC) != 6 {
		srcMAC = zeroMAC
	}

	sh := &SendHandle{
		handle:  handle,
		srcPort: uint16(cfg.Port),
		tcpF:    TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:    uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: srcMAC}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      184,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: 184,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		// Option set: prefer the transport-supplied builder (syntfo installs
		// one carrying the TFO option, T1.2). Fall back to the legacy
		// option set when no builder is installed so non-syntfo callers
		// (tests, other transports) keep the pre-T1.2 behaviour.
		if h.synOptionsBuilder != nil {
			tcp.Options = h.synOptionsBuilder(tsVal)
		} else {
			tcp.Options = []layers.TCPOption{
				{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
				{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
				{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
				{OptionType: layers.TCPOptionKindNop},
				{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
			}
			binary.BigEndian.PutUint32(tcp.Options[2].OptionData[0:4], tsVal)
			binary.BigEndian.PutUint32(tcp.Options[2].OptionData[4:8], 0)
		}
		// Sequence: T0.3 routed the seq-entropy fix to T1.2. The legacy
		// formula `1 + (counter & 0x7)` produced only 8 distinct values,
		// which causes silent dedup drops in SYN-only mode (paqet's normal
		// PA flow never noticed because it had a proper full-entropy seq
		// in the non-SYN branch). We are forging the SYN here — this is NOT
		// the kernel's TCP stack picking an ISN, so we must supply the
		// entropy explicitly. The syntfo transport (which owns the wire
		// format) installs a derivation matching the non-SYN branch's
		// `time + counter<<7` template, giving the full 32-bit range. A
		// nil deriver keeps legacy behaviour for backward compatibility
		// with non-syntfo callers.
		if h.synSeqDeriver != nil {
			tcp.Seq = h.synSeqDeriver(h.time, counter)
		} else {
			tcp.Seq = 1 + (counter & 0x7)
		}
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		}
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[4:8], tsEcr)
		seq := h.time + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(dstPort, f)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		// T4.8: surface serialize failures via a counter + one-shot warn
		// log. Without this, KCP swallows the error returned through
		// PacketConn.WriteTo and the failure mode is "no packets on the
		// wire" with zero diagnostic. The warn fires only on the first
		// failure (CompareAndSwap on warnLoggedSerialize) so a steady-
		// state bug does not spam the log per packet.
		h.writeSerializeErr.Add(1)
		if h.warnLoggedSerialize.CompareAndSwap(false, true) {
			flog.Warnf("socket: gopacket SerializeLayers failed (further failures suppressed; see SendHandle counters): %v", err)
		}
		return err
	}
	if err := h.handle.WritePacketData(buf.Bytes()); err != nil {
		// Mirror the diagnostic for pcap-level write errors. KCP will
		// surface the failure as "no packets on the wire" otherwise.
		h.writePcapErr.Add(1)
		if h.warnLoggedPcap.CompareAndSwap(false, true) {
			flog.Warnf("socket: pcap WritePacketData failed (further failures suppressed; see SendHandle counters): %v", err)
		}
		return err
	}
	return nil
}

// WriteSerializeErrCount returns the number of gopacket.SerializeLayers
// failures observed by this handle. Exposed for tests and a future metrics
// scraper; the counter is incremented in-place by Write on every failed
// serialize.
func (h *SendHandle) WriteSerializeErrCount() uint64 {
	return h.writeSerializeErr.Load()
}

// WritePcapErrCount returns the number of pcap WritePacketData failures
// observed by this handle. Same rationale as WriteSerializeErrCount.
func (h *SendHandle) WritePcapErrCount() uint64 {
	return h.writePcapErr.Load()
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

// SetSYNOptionsBuilder installs the SYN-option builder used in the SYN branch
// of buildTCPHeader. Callers (today: only the syntfo transport) wire this at
// construction time; subsequent Writes pick up the new builder via the
// SendHandle's pointer to it. Passing nil restores the default option set.
//
// Concurrency: this is intended to be called once during transport setup,
// before any Write calls. It is safe to call concurrently with Write only
// in the sense that the pointer assignment itself is word-aligned and
// goroutines will observe either the old or new builder per call, never a
// torn pointer. There is intentionally no mutex because the use case is
// "install once at startup," not "swap mid-flight."
func (h *SendHandle) SetSYNOptionsBuilder(b SYNOptionsBuilder) {
	h.synOptionsBuilder = b
}

// SetSYNSeqDeriver installs the SYN sequence-number deriver. See the
// SYNSeqDeriver doc and the comment in buildTCPHeader for why this is a
// hook rather than a hardcoded derivation in this package. Same concurrency
// caveats as SetSYNOptionsBuilder.
func (h *SendHandle) SetSYNSeqDeriver(d SYNSeqDeriver) {
	h.synSeqDeriver = d
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
