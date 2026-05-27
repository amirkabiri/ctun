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
	"ctun/internal/tnet"
	"ctun/internal/tnet/kcp"
	"ctun/internal/transport"
	"ctun/internal/transport/syntfo"
)

type Server struct {
	cfg       *conf.Conf
	transport transport.Transport
	syntfo    *syntfo.Transport // non-nil iff transport is the syn-tfo impl
	wg        sync.WaitGroup
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{
		cfg: cfg,
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

	tr, err := transport.New(s.cfg.TransportImpl, transport.Config{
		Ctx:     ctx,
		Network: &s.cfg.Network,
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
