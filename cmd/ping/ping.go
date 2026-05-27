package ping

import (
	"context"
	"log"
	"net/netip"

	"ctun/internal/conf"
	"ctun/internal/transport"
	_ "ctun/internal/transport/syntfo" // register the "syn-tfo" transport

	"github.com/spf13/cobra"
)

var (
	confPath string
	payload  string
)

func init() {
	Cmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file.")
	Cmd.Flags().StringVar(&payload, "payload", "PING", "The string payload to send in the packet")
}

var Cmd = &cobra.Command{
	Use:   "ping [flags]",
	Short: "Sends a single raw TCP packet with a custom payload.",
	Run: func(cmd *cobra.Command, args []string) {
		sendPacket()
	},
}

func sendPacket() {
	cfg, err := conf.LoadFromFile(confPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if cfg.Role != "client" {
		log.Fatalf("ping command requires client configuration")
	}

	netCfg := cfg.Network
	tr, err := transport.New(cfg.TransportImpl, transport.Config{
		Ctx:     context.TODO(),
		Network: &netCfg,
	})
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}
	defer tr.Close()

	log.Printf("Sending packet from IPv4:%s IPv6:%s to %s via %s...", cfg.Network.IPv4.Addr, cfg.Network.IPv6.Addr, cfg.Server.Addr.String(), cfg.Network.Interface.Name)
	log.Printf("Payload: \"%s\" (%d bytes)", payload, len(payload))

	dst, ok := netip.AddrFromSlice(cfg.Server.Addr.IP)
	if !ok {
		log.Fatalf("invalid server address: %v", cfg.Server.Addr.IP)
	}
	if dst.Is4In6() {
		dst = dst.Unmap()
	}
	if err := tr.Send(context.TODO(), &transport.Datagram{
		Data:    []byte(payload),
		DstAddr: netip.AddrPortFrom(dst, uint16(cfg.Server.Addr.Port)),
	}); err != nil {
		log.Fatalf("Failed to send packet: %v", err)
	}
	log.Printf("Packet sent successfully!")
}
