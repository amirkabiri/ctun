package syntfo

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// serializeTCPOptions runs gopacket's TCP serializer over the option list
// and returns just the option bytes (the section between the 20-byte fixed
// TCP header and the payload). It is a small helper to keep the tests
// focused on options rather than on the full TCP header binary.
func serializeTCPOptions(t *testing.T, opts []layers.TCPOption) []byte {
	t.Helper()

	// We serialize a minimal TCP layer onto an IPv4 carrier so the
	// checksum machinery has something to bite onto (gopacket panics in
	// ComputeChecksums when no network layer is set). The IPv4 layer is
	// discarded; we only return the option bytes.
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		Window:  65535,
		Options: opts,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, sopts, ip, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}

	all := buf.Bytes()
	// IPv4 header is 20 bytes (IHL=5); TCP fixed header is 20 bytes; the
	// rest is options + payload (no payload in this test).
	ipHL := int(all[0]&0x0F) * 4
	tcpStart := ipHL
	tcpHL := int(all[tcpStart+12]>>4) * 4
	return all[tcpStart+20 : tcpStart+tcpHL]
}

func TestSYNOptionsBuilder_ByteForByte(t *testing.T) {
	cookie := DefaultStaticCookie()
	const tsVal uint32 = 0x12345678

	opts := BuildSYNOptions(cookie, tsVal)
	got := serializeTCPOptions(t, opts)

	// Expected layout (32 bytes total):
	//   MSS              : 02 04 05 b4
	//   SACK-permitted   : 04 02
	//   Timestamps       : 08 0a [TSval=0x12345678][TSecr=0]
	//   NOP              : 01
	//   WindowScale      : 03 03 08
	//   NOP              : 01
	//   NOP              : 01
	//   TFO (Kind=34=0x22, Len=10): 22 0a C7 55 00 01 DE AD BE EF
	want := []byte{
		0x02, 0x04, 0x05, 0xb4, // MSS
		0x04, 0x02, // SACK-perm
		0x08, 0x0a, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, // Timestamps
		0x01,             // NOP
		0x03, 0x03, 0x08, // WindowScale
		0x01,                                                       // NOP (alignment pad)
		0x01,                                                       // NOP (alignment pad)
		0x22, 0x0a, 0xC7, 0x55, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, // TFO
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("serialized options mismatch\n got: % x\nwant: % x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("option block length = %d, want 32", len(got))
	}
}

func TestSYNOptions_HeaderSizeAlignment(t *testing.T) {
	// The TCP DataOffset field expresses header length in 32-bit words, so
	// the serialized header (fixed 20 bytes + options + any padding) must
	// be a multiple of 4. If our option-list arithmetic ever loses an
	// alignment NOP, gopacket will silently zero-pad — but a manual
	// inspection on the wire would show extra zero bytes after the TFO
	// option, which is hostile to anyone matching by pattern. So we assert
	// no padding is needed: the option block alone is already 32 bytes.
	cookies := [][CookieSize]byte{
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DefaultStaticCookie(),
		{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	}
	for i, c := range cookies {
		opts := BuildSYNOptions(c, uint32(i))
		got := serializeTCPOptions(t, opts)
		if len(got)%4 != 0 {
			t.Errorf("cookie %d: option block length %d not a multiple of 4", i, len(got))
		}
		if len(got) != 32 {
			t.Errorf("cookie %d: option block length = %d, want 32 (no padding expected)", i, len(got))
		}
	}
}

func TestSYNOptions_Parseable(t *testing.T) {
	cookie := DefaultStaticCookie()
	const tsVal uint32 = 0xDEADC0DE

	// Serialize a full IPv4 + TCP packet so we can re-parse it from
	// LayerTypeIPv4 and reach the TCP options through gopacket's normal
	// decode path.
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		Window:  65535,
		Options: BuildSYNOptions(cookie, tsVal),
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, sopts, ip, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		t.Fatalf("packet parse error: %v", pkt.ErrorLayer().Error())
	}
	parsedTCP, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatalf("no TCP layer in parsed packet")
	}

	// Count Kind=34 occurrences; assert exactly one with length 10 and the
	// expected cookie bytes.
	var tfoCount int
	for _, o := range parsedTCP.Options {
		if o.OptionType == TFOOptionKind {
			tfoCount++
			if o.OptionLength != TFOOptionLength {
				t.Errorf("TFO option length = %d, want %d", o.OptionLength, TFOOptionLength)
			}
			if !bytes.Equal(o.OptionData, cookie[:]) {
				t.Errorf("TFO cookie = % x, want % x", o.OptionData, cookie[:])
			}
		}
	}
	if tfoCount != 1 {
		t.Fatalf("found %d TFO options, want exactly 1", tfoCount)
	}

	// Sanity: MSS option should still be present and unchanged from the
	// pre-T1.2 paqet value (0x05b4 = 1460).
	var mssFound bool
	for _, o := range parsedTCP.Options {
		if o.OptionType == layers.TCPOptionKindMSS {
			mssFound = true
			if !bytes.Equal(o.OptionData, []byte{0x05, 0xb4}) {
				t.Errorf("MSS value = % x, want 05 b4", o.OptionData)
			}
		}
	}
	if !mssFound {
		t.Errorf("MSS option missing from parsed SYN")
	}
}

func TestSYNOptions_ChecksumValid(t *testing.T) {
	cookie := DefaultStaticCookie()
	const tsVal uint32 = 0x01020304

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		Window:  65535,
		Options: BuildSYNOptions(cookie, tsVal),
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, sopts, ip, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}

	// Parse the bytes back and verify the checksum on the wire matches what
	// gopacket computes from the parsed packet. A failing checksum is the
	// most common gopacket-misuse symptom (forgetting
	// SetNetworkLayerForChecksum / ComputeChecksums).
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		t.Fatalf("packet parse error: %v", pkt.ErrorLayer().Error())
	}
	parsedTCP, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatalf("no TCP layer in parsed packet")
	}
	parsedIP, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		t.Fatalf("no IPv4 layer in parsed packet")
	}

	if err := parsedTCP.SetNetworkLayerForChecksum(parsedIP); err != nil {
		t.Fatalf("re-SetNetworkLayerForChecksum: %v", err)
	}
	err, result := parsedTCP.VerifyChecksum()
	if err != nil {
		t.Fatalf("VerifyChecksum: %v", err)
	}
	if !result.Valid {
		t.Fatalf("TCP checksum invalid: wire=0x%04x correct=0x%04x", parsedTCP.Checksum, result.Correct)
	}
}

func TestSeqEntropy_SYN(t *testing.T) {
	// T0.3 found the pre-T1.2 derivation (`1 + counter & 0x7`) yielded only
	// 8 distinct sequence numbers across many calls — the silent dedup-bug
	// that motivated the fix. Lock in the new derivation by sampling 1024
	// counter values and asserting we observe a sequence-number set with
	// well over 512 distinct entries (in practice, all 1024 are distinct
	// for any fixed timeBase).
	const timeBase uint32 = 0xCAFEBABE
	seen := make(map[uint32]struct{}, 1024)
	for c := uint32(1); c <= 1024; c++ {
		seen[SYNSeq(timeBase, c)] = struct{}{}
	}
	if len(seen) <= 512 {
		t.Fatalf("SYNSeq distinct values = %d, want > 512", len(seen))
	}

	// Also assert the value range spans more than the legacy 8-value
	// window. With (counter << 7) the min and max across counter=1..1024
	// should differ by roughly (1023 << 7) = 130944.
	var minV, maxV uint32 = ^uint32(0), 0
	for s := range seen {
		if s < minV {
			minV = s
		}
		if s > maxV {
			maxV = s
		}
	}
	span := maxV - minV
	if span < 1024 {
		t.Fatalf("SYNSeq span across 1024 counters = %d, want >= 1024", span)
	}
}

// TestSYNOptionsBuilder_PreservesTSValBigEndian sanity-checks that the
// tsVal argument lands big-endian in the Timestamps option payload —
// gopacket does not enforce this, and a future refactor swapping endian
// would silently produce non-RFC-7323 timestamps.
func TestSYNOptionsBuilder_PreservesTSValBigEndian(t *testing.T) {
	const tsVal uint32 = 0x11223344
	opts := BuildSYNOptions(DefaultStaticCookie(), tsVal)

	var ts *layers.TCPOption
	for i := range opts {
		if opts[i].OptionType == layers.TCPOptionKindTimestamps {
			ts = &opts[i]
			break
		}
	}
	if ts == nil {
		t.Fatalf("Timestamps option missing")
	}
	if len(ts.OptionData) != 8 {
		t.Fatalf("Timestamps payload length = %d, want 8", len(ts.OptionData))
	}
	if got := binary.BigEndian.Uint32(ts.OptionData[0:4]); got != tsVal {
		t.Errorf("TSval = 0x%08x, want 0x%08x", got, tsVal)
	}
	if got := binary.BigEndian.Uint32(ts.OptionData[4:8]); got != 0 {
		t.Errorf("TSecr = 0x%08x, want 0 (initial SYN per RFC 7323)", got)
	}
}
