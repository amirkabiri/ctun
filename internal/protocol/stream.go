// Stream-control sub-frames carried inside FlagData / FlagKeepalive
// Messages. See the package doc for the full layout description.
//
// This file owns the binary encoding of the legacy paqet Proto control
// messages (PPING/PPONG/PTCPF/PTCP/PUDP) — folded into the ctun wire format
// without gob.

package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"ctun/internal/conf"
	"ctun/internal/tnet"
)

// PType identifies a stream-control sub-frame within a Message payload.
// PType bytes are independent of (but stable across) Flags values.
type PType = byte

// Stream-control sub-frame identifiers. Values mirror paqet's legacy
// numbering so on-the-wire compatibility with previously-captured traces
// is preserved at the sub-frame layer (the outer envelope is new).
const (
	PPING PType = 0x01
	PPONG PType = 0x02
	PTCPF PType = 0x03
	PTCP  PType = 0x04
	PUDP  PType = 0x05
)

// Bit positions for the TCPF bitfield. See the package doc.
const (
	tcpfBitFIN uint16 = 1 << 0
	tcpfBitSYN uint16 = 1 << 1
	tcpfBitRST uint16 = 1 << 2
	tcpfBitPSH uint16 = 1 << 3
	tcpfBitACK uint16 = 1 << 4
	tcpfBitURG uint16 = 1 << 5
	tcpfBitECE uint16 = 1 << 6
	tcpfBitCWR uint16 = 1 << 7
	tcpfBitNS  uint16 = 1 << 8

	tcpfBitsUsed uint16 = tcpfBitFIN | tcpfBitSYN | tcpfBitRST | tcpfBitPSH |
		tcpfBitACK | tcpfBitURG | tcpfBitECE | tcpfBitCWR | tcpfBitNS
)

// ErrInvalidSubFrame is returned when a Message payload cannot be parsed as
// the expected stream-control sub-frame (unknown PType, truncated body,
// invalid addresses, or reserved bits set on the wire).
var ErrInvalidSubFrame = errors.New("protocol: invalid stream-control sub-frame")

// Proto is the in-memory representation of a stream-control message. It
// mirrors the legacy paqet shape so call-sites can be migrated mechanically.
type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
}

// EncodeProto serialises p into a Message ready for the wire. The chosen
// Flags value follows the mapping documented in the package doc.
func EncodeProto(p *Proto) (*Message, error) {
	var (
		flags   Flags
		payload []byte
	)
	switch p.Type {
	case PPING, PPONG:
		flags = FlagKeepalive
		payload = []byte{p.Type}
	case PTCPF:
		flags = FlagData
		if len(p.TCPF) > 255 {
			return nil, fmt.Errorf("%w: PTCPF count %d exceeds 255", ErrInvalidSubFrame, len(p.TCPF))
		}
		payload = make([]byte, 2+2*len(p.TCPF))
		payload[0] = p.Type
		payload[1] = byte(len(p.TCPF))
		for i, f := range p.TCPF {
			binary.BigEndian.PutUint16(payload[2+2*i:4+2*i], packTCPF(f))
		}
	case PTCP, PUDP:
		flags = FlagData
		if p.Addr == nil {
			return nil, fmt.Errorf("%w: address required for sub-type 0x%02x", ErrInvalidSubFrame, p.Type)
		}
		host := p.Addr.Host
		if len(host) > 255 {
			return nil, fmt.Errorf("%w: host length %d exceeds 255", ErrInvalidSubFrame, len(host))
		}
		if p.Addr.Port < 0 || p.Addr.Port > 65535 {
			return nil, fmt.Errorf("%w: port %d out of range", ErrInvalidSubFrame, p.Addr.Port)
		}
		payload = make([]byte, 1+1+len(host)+2)
		payload[0] = p.Type
		payload[1] = byte(len(host))
		copy(payload[2:2+len(host)], host)
		binary.BigEndian.PutUint16(payload[2+len(host):], uint16(p.Addr.Port))
	default:
		return nil, fmt.Errorf("%w: unknown PType 0x%02x", ErrInvalidSubFrame, p.Type)
	}
	return &Message{Flags: flags, Payload: payload}, nil
}

// DecodeProto parses a Message into a Proto. The Message's Flags must match
// the expected mapping for the embedded PType.
func DecodeProto(m *Message) (*Proto, error) {
	if len(m.Payload) < 1 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidSubFrame)
	}
	pt := m.Payload[0]
	body := m.Payload[1:]
	p := &Proto{Type: pt}
	switch pt {
	case PPING, PPONG:
		if m.Flags != FlagKeepalive {
			return nil, fmt.Errorf("%w: PType 0x%02x requires FlagKeepalive, got %d", ErrInvalidSubFrame, pt, m.Flags)
		}
		if len(body) != 0 {
			return nil, fmt.Errorf("%w: PType 0x%02x must have empty body, got %d bytes", ErrInvalidSubFrame, pt, len(body))
		}
	case PTCPF:
		if m.Flags != FlagData {
			return nil, fmt.Errorf("%w: PTCPF requires FlagData, got %d", ErrInvalidSubFrame, m.Flags)
		}
		if len(body) < 1 {
			return nil, fmt.Errorf("%w: PTCPF body too short", ErrInvalidSubFrame)
		}
		count := int(body[0])
		if len(body) != 1+2*count {
			return nil, fmt.Errorf("%w: PTCPF body length %d disagrees with count %d", ErrInvalidSubFrame, len(body), count)
		}
		if count > 0 {
			p.TCPF = make([]conf.TCPF, count)
			for i := 0; i < count; i++ {
				bits := binary.BigEndian.Uint16(body[1+2*i : 3+2*i])
				if bits&^tcpfBitsUsed != 0 {
					return nil, fmt.Errorf("%w: PTCPF reserved bits set: 0x%04x", ErrInvalidSubFrame, bits)
				}
				p.TCPF[i] = unpackTCPF(bits)
			}
		}
	case PTCP, PUDP:
		if m.Flags != FlagData {
			return nil, fmt.Errorf("%w: PType 0x%02x requires FlagData, got %d", ErrInvalidSubFrame, pt, m.Flags)
		}
		if len(body) < 1 {
			return nil, fmt.Errorf("%w: address sub-frame truncated", ErrInvalidSubFrame)
		}
		hostLen := int(body[0])
		if len(body) != 1+hostLen+2 {
			return nil, fmt.Errorf("%w: address body length %d disagrees with hostLen %d", ErrInvalidSubFrame, len(body), hostLen)
		}
		host := string(body[1 : 1+hostLen])
		port := int(binary.BigEndian.Uint16(body[1+hostLen:]))
		p.Addr = &tnet.Addr{Host: host, Port: port}
	default:
		return nil, fmt.Errorf("%w: unknown PType 0x%02x", ErrInvalidSubFrame, pt)
	}
	return p, nil
}

// Read parses one stream-control Proto from r. It is the binary replacement
// for the gob-based legacy Proto.Read method and preserves its signature.
func (p *Proto) Read(r io.Reader) error {
	m, err := ReadMessage(r)
	if err != nil {
		return err
	}
	got, err := DecodeProto(m)
	if err != nil {
		return err
	}
	*p = *got
	return nil
}

// Write serialises p and emits it on w. Binary replacement for the legacy
// gob-based Proto.Write.
func (p *Proto) Write(w io.Writer) error {
	m, err := EncodeProto(p)
	if err != nil {
		return err
	}
	return WriteMessage(w, m)
}

func packTCPF(f conf.TCPF) uint16 {
	var b uint16
	if f.FIN {
		b |= tcpfBitFIN
	}
	if f.SYN {
		b |= tcpfBitSYN
	}
	if f.RST {
		b |= tcpfBitRST
	}
	if f.PSH {
		b |= tcpfBitPSH
	}
	if f.ACK {
		b |= tcpfBitACK
	}
	if f.URG {
		b |= tcpfBitURG
	}
	if f.ECE {
		b |= tcpfBitECE
	}
	if f.CWR {
		b |= tcpfBitCWR
	}
	if f.NS {
		b |= tcpfBitNS
	}
	return b
}

func unpackTCPF(b uint16) conf.TCPF {
	return conf.TCPF{
		FIN: b&tcpfBitFIN != 0,
		SYN: b&tcpfBitSYN != 0,
		RST: b&tcpfBitRST != 0,
		PSH: b&tcpfBitPSH != 0,
		ACK: b&tcpfBitACK != 0,
		URG: b&tcpfBitURG != 0,
		ECE: b&tcpfBitECE != 0,
		CWR: b&tcpfBitCWR != 0,
		NS:  b&tcpfBitNS != 0,
	}
}
