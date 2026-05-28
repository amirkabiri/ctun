package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"ctun/internal/conf"
	"ctun/internal/flog"
	"ctun/internal/session"
	"ctun/internal/tnet"
	"ctun/internal/tnet/kcp"
	"ctun/internal/transport"
	"ctun/internal/transport/syntfo"
)

type Server struct {
	cfg       *conf.Conf
	mgr       *session.Manager
	transport transport.Transport
	syntfo    *syntfo.Transport // non-nil iff transport is the syn-tfo impl
	wg        sync.WaitGroup
}

func New(cfg *conf.Conf, mgr *session.Manager) (*Server, error) {
	s := &Server{
		cfg: cfg,
		mgr: mgr,
	}

	return s, nil
}

func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received, initiating graceful shutdown...")
		cancel()
	}()

	// Plumb the session manager through ExtraParams (T1.1's transport-specific
	// escape hatch). The syn-tfo transport recognises the key and wires the
	// SessionCookieProvider; non-syn-tfo transports ignore it. Documented in
	// docs/implementation-doc.md → T3.2 → "Where manager is plumbed".
	tr, err := transport.New(s.cfg.TransportImpl, transport.Config{
		Ctx:     ctx,
		Network: &s.cfg.Network,
		ExtraParams: map[string]any{
			syntfo.ExtraParamSessionManager: s.mgr,
		},
	})
	if err != nil {
		return fmt.Errorf("could not create transport: %w", err)
	}
	s.transport = tr
	// Preserve the syntfo-specific handle so the existing TCP-flag plumbing
	// in handleStrm continues to work. When more transports land (T6.x), this
	// surface will need to be generalised — until then, it is the simplest
	// path to a zero-behaviour-change refactor.
	if st, ok := tr.(*syntfo.Transport); ok {
		s.syntfo = st
		// T4.9: install the per-Transport HELLO handler that drives
		// session.RunServerHandshake for every inbound HELLO. Before
		// this wiring, the syn-tfo transport shipped the primitives
		// (HelloHandler, SessionCookieProvider.Bind) but no production
		// driver invoked them — every client request died with
		// secureConn.WriteTo returning ErrNoSession. Installing this
		// handler is what closes the loop. The handler must be in place
		// BEFORE kcp.Listen because clients may race the server: a
		// HELLO arriving before the handler is installed would be
		// dropped at the gate (helloHandler==nil branch).
		if err := st.InstallServerHandshakeHandler(ctx, s.mgr.AuthKey()); err != nil {
			return fmt.Errorf("install server handshake handler: %w", err)
		}
	}

	listener, err := kcp.Listen(s.cfg.Transport.KCP, tr)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	defer listener.Close()
	flog.Infof("Server started - listening for packets on :%d", s.cfg.Listen.Addr.Port)

	s.wg.Go(func() {
		s.listen(ctx, listener)
	})

	s.wg.Wait()
	flog.Infof("Server shutdown completed")
	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			flog.Errorf("failed to accept connection: %v", err)
			continue
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		s.wg.Go(func() {
			defer conn.Close()
			s.handleConn(ctx, conn)
		})
	}
}
