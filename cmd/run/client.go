package run

import (
	"context"
	"ctun/internal/client"
	"ctun/internal/conf"
	"ctun/internal/flog"
	"ctun/internal/forward"
	"ctun/internal/socks"
	"os"
	"os/signal"
	"syscall"
)

func startClient(cfg *conf.Conf) {
	flog.Infof("Starting client...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received, initiating graceful shutdown...")
		cancel()
	}()

	// Firewall rules must be in place before the client starts injecting
	// synthetic SYNs via pcap; otherwise the host kernel will RST the
	// stray traffic on the tunnel port. T4.4 wires setupFirewall here;
	// cleanup is deferred via runWithFirewall so the SIGINT/SIGTERM
	// path above (which cancels ctx) and any panic both trigger rule
	// removal. firewall.InstallCleanup (inside setupFirewall) also
	// listens on ctx.Done(), so the same cancel() drives both ctun's
	// shutdown and the firewall cleanup.
	cleanup, err := setupFirewall(ctx, cfg, false /* isServer */)
	if err != nil {
		flog.Fatalf("Failed to set up firewall: %v", err)
	}

	runWithFirewall(cleanup, func() {
		c, err := client.New(cfg, newSessionManager(cfg))
		if err != nil {
			flog.Fatalf("Failed to initialize client: %v", err)
		}
		if err := c.Start(ctx); err != nil {
			flog.Infof("Client encountered an error: %v", err)
		}

		for _, ss := range cfg.SOCKS5 {
			s, err := socks.New(c)
			if err != nil {
				flog.Fatalf("Failed to initialize SOCKS5: %v", err)
			}
			if err := s.Start(ctx, ss); err != nil {
				flog.Fatalf("SOCKS5 encountered an error: %v", err)
			}
		}
		for _, ff := range cfg.Forward {
			f, err := forward.New(c, ff.Listen.String(), ff.Target.String())
			if err != nil {
				flog.Fatalf("Failed to initialize Forward: %v", err)
			}
			if err := f.Start(ctx, ff.Protocol); err != nil {
				flog.Infof("Forward encountered an error: %v", err)
			}
		}

		<-ctx.Done()
	})
}
