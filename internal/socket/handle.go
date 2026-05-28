package socket

import (
	"ctun/internal/conf"
	"fmt"
	"runtime"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// pcapPollTimeout bounds how long a single pcap.ReadPacketData call
// blocks before returning pcap.NextErrorTimeoutExpired. Pre-T4.9 this
// was pcap.BlockForever, which made socket.PacketConn.ReadFrom's
// deadline check (in socket.go) a no-op — once the underlying pcap
// call was in flight, only an arriving packet (or handle close) could
// release it. That meant ctx cancellation and read deadlines were
// unobservable for the lifetime of a quiet recv, which broke clean
// shutdown on SIGTERM and broke the wrong-PSK handshake's ability to
// abandon on context timeout. socket.PacketConn.ReadFrom now loops
// over timeout returns and re-checks ctx/deadline between iterations
// (see socket.go), so this constant controls responsiveness: 250 ms
// matches the integration sniffer (test/integration/pcap_helpers.go)
// and is well under the handshake driver's 200 ms per-attempt budget.
const pcapPollTimeout = 250 * time.Millisecond

func newHandle(cfg *conf.Network) (*pcap.Handle, error) {
	// On Windows, use the GUID field to construct the NPF device name
	// On other platforms, use the interface name directly
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}

	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %v", cfg.Interface.Name, err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetBufferSize(cfg.PCAP.Sockbuf); err != nil {
		return nil, fmt.Errorf("failed to set pcap buffer size to %d: %v", cfg.PCAP.Sockbuf, err)
	}

	if err = inactive.SetSnapLen(65536); err != nil {
		return nil, fmt.Errorf("failed to set pcap snap length: %v", err)
	}
	if err = inactive.SetPromisc(true); err != nil {
		return nil, fmt.Errorf("failed to enable promiscuous mode: %v", err)
	}
	if err = inactive.SetTimeout(pcapPollTimeout); err != nil {
		return nil, fmt.Errorf("failed to set pcap timeout: %v", err)
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("failed to enable immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
	}

	return handle, nil
}
