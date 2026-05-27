package run

import (
	"context"
	"ctun/internal/conf"
	"ctun/internal/crypto"
	"ctun/internal/flog"
	"ctun/internal/server"
	"ctun/internal/session"
)

func startServer(cfg *conf.Conf) {
	flog.Infof("Starting server...")

	// Firewall rules must be in place before the server starts injecting
	// synthetic packets via pcap; otherwise the host kernel will RST the
	// inbound SYNs that don't match any listening socket. T4.4 wires
	// setupFirewall (cmd/run/firewall_setup.go) here; cleanup is deferred
	// via runWithFirewall so SIGINT/SIGTERM (handled inside server.Start)
	// and panic both trigger rule removal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup, err := setupFirewall(ctx, cfg, true /* isServer */)
	if err != nil {
		flog.Fatalf("Failed to set up firewall: %v", err)
	}

	runWithFirewall(cleanup, func() {
		mgr := newSessionManager(cfg)

		srv, err := server.New(cfg, mgr)
		if err != nil {
			flog.Fatalf("Failed to initialize server: %v", err)
		}
		if err := srv.Start(); err != nil {
			flog.Fatalf("Server encountered an error: %v", err)
		}
	})
}

// newSessionManager constructs the process's session.Manager from the PSK
// the config exposes. T3.2 sources the PSK from transport.kcp.key — paqet's
// existing field — to avoid introducing a new top-level psk: knob in this
// task (deferred to a Phase-3+ config refresh per the T3.2 brief). Both
// client and server use the same derivation so the authKey matches; only
// the manager's role (issuer on the server, binder on the client) differs.
//
// An empty key (kcp.block: "none" / "null") yields a valid but predictable
// authKey — HKDF accepts any IKM length. The validator at conf load-time
// already rejects empty keys for non-"none" block ciphers, so this only
// hits when the operator has explicitly opted out of KCP-layer encryption.
// For T3.2's scope (which only derives keys, no cookie validation yet)
// this is acceptable; T3.3 will revisit when authentication actually
// gates traffic.
func newSessionManager(cfg *conf.Conf) *session.Manager {
	psk := []byte(cfg.Transport.KCP.Key)
	encKey, authKey := crypto.DeriveKeys(psk)
	return session.NewManager(encKey, authKey)
}
