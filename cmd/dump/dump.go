package dump

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ctun/internal/conf"
	"ctun/internal/transport"
	_ "ctun/internal/transport/syntfo" // register the "syn-tfo" transport

	"github.com/spf13/cobra"
)

var (
	iface   string
	port    int
	snaplen int
	promisc bool
)

var confPath string

func init() {
	Cmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file.")
}

var Cmd = &cobra.Command{
	Use:   "dump",
	Short: "A raw packet dumper that logs TCP payloads for a given port.",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := conf.LoadFromFile(confPath)
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}

		if cfg.Role != "server" {
			log.Fatalf("dump command requires server configuration")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		netCfg := cfg.Network
		tr, err := transport.New(cfg.TransportImpl, transport.Config{
			Ctx:     ctx,
			Network: &netCfg,
		})
		if err != nil {
			log.Fatalf("Failed to create transport: %v", err)
		}
		defer tr.Close()

		// The dump command predates the Transport interface and uses
		// SetReadDeadline to drive a poll loop. That method lives on
		// net.PacketConn, not on the Transport contract, so we pull it via
		// the PacketConnProvider capability. A transport without that
		// capability simply can't drive `dump` — log loudly rather than
		// silently mis-behave.
		pcProvider, ok := tr.(transport.PacketConnProvider)
		if !ok {
			log.Fatalf("transport %T does not provide a net.PacketConn; `dump` requires it", tr)
		}
		packetConn := pcProvider.PacketConn()

		log.Printf("listening for packets on :%d, (Press Ctrl+C to exit)", cfg.Listen.Addr.Port)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					payload := make([]byte, 65535)
					packetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					n, srcAddr, err := packetConn.ReadFrom(payload)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						log.Printf("Failed to read from socket: %v", err)
						continue
					}
					go handlePacket(srcAddr, cfg.Listen.Addr, payload[:n])
				}
			}
		}()
		<-sigChan
		log.Printf("Shutdown signal received, exiting.")
		cancel()
	},
}

func handlePacket(srcAddr, dstAddr net.Addr, payload []byte) {
	var sb strings.Builder
	fmt.Fprintf(&sb,
		"[%s] Packet: %s -> %s | Length: %d bytes\n",
		time.Now().Format("15:04:05.000"),
		srcAddr,
		dstAddr,
		len(payload),
	)
	sb.WriteString("--- PAYLOAD (HEX DUMP) ---\n")
	sb.WriteString(hex.Dump(payload))
	sb.WriteString("--------------------------")

	fmt.Println(sb.String())
}
