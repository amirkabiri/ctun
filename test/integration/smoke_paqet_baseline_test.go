// Package integration contains end-to-end tests that drive the ctun binary
// as a subprocess. They require root (raw sockets / pcap) and are skipped
// otherwise.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"text/template"
	"time"

	"golang.org/x/net/proxy"
)

// Test_Smoke_PaqetBaseline boots an unmodified-default ctun server + client
// (paqet's [PA] flag profile) on loopback and drives an HTTP GET through the
// SOCKS5 listener exposed by the client. It is a baseline so any later breakage
// in ctun-specific code is attributable to that change rather than the inherited
// transport. T1.5 supersedes this test and T4.6 removes it.
//
// Subtests:
//   - first-run:  full boot/teardown cycle, asserts 200 and expected body.
//   - second-run: identical to first-run; proves teardown is clean and resources
//     (ports, pcap handles, child PIDs) do not leak.
//
// To run a single sub-test:
//
//	sudo go test ./test/integration/ -run 'Smoke_PaqetBaseline/first-run' -v
func Test_Smoke_PaqetBaseline(t *testing.T) {
	t.Skip("superseded by Test_Smoke_SynTfo; will be deleted in T4.6")
	skipUnlessRunnable(t)

	bin := buildCtunBinary(t)

	t.Run("first-run", func(t *testing.T) {
		runBaselineRoundTrip(t, bin)
	})
	t.Run("second-run", func(t *testing.T) {
		runBaselineRoundTrip(t, bin)
	})
}

// skipUnlessRunnable centralises the gating for the whole integration suite.
// The defaults are aggressively conservative: a contributor running
// `go test ./...` as a non-root user should never see a failure here.
func skipUnlessRunnable(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration smoke test in -short mode")
	}
	if os.Getuid() != 0 {
		// Best-effort hint of *who* we are running as so the message is helpful
		// in CI logs.
		who := "non-root"
		if u, err := user.Current(); err == nil {
			who = u.Username
		}
		t.Skipf("integration test requires root for raw sockets / pcap (running as %s); rerun with sudo and -short=false", who)
	}
}

// runBaselineRoundTrip is the shared per-iteration body. It is idempotent in
// the sense that every call gets its own tempdir, its own free port pair, and
// its own subprocess group.
func runBaselineRoundTrip(t *testing.T, ctunBin string) {
	t.Helper()

	tunnelPort, socksPort := allocLoopbackPorts(t)
	iface := lookupTestIface()
	sharedKey := newSharedKey(t)

	// Spin the destination HTTP server up first so the server side has
	// somewhere to dial as soon as a SOCKS5 CONNECT arrives.
	const expectedBody = "ctun-baseline-ok"
	httpAddr := startTestHTTPServer(t, expectedBody)

	// Materialise the YAML fixtures with the per-iteration parameters.
	scratch := t.TempDir()
	serverCfg := renderFixture(t, "server-pa.yaml", filepath.Join(scratch, "server.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})
	clientCfg := renderFixture(t, "client-pa.yaml", filepath.Join(scratch, "client.yaml"), fixtureParams{
		TunnelPort: tunnelPort,
		SocksPort:  socksPort,
		Iface:      iface,
		RouterMAC:  loopbackRouterMAC,
		SharedKey:  sharedKey,
	})

	// Start server, then client. Cleanup runs in reverse order via t.Cleanup.
	serverLog := startCtun(t, ctunBin, serverCfg, "server")
	waitFor(t, fmt.Sprintf("server listening on :%d", tunnelPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", tunnelPort)
	}, serverLog)

	clientLog := startCtun(t, ctunBin, clientCfg, "client")
	waitFor(t, fmt.Sprintf("SOCKS5 listening on :%d", socksPort), 10*time.Second, func() bool {
		return tcpPortListening("127.0.0.1", socksPort)
	}, clientLog)

	// Drive an HTTP request *through* the SOCKS5 listener.
	body := doHTTPThroughSOCKS5(t, fmt.Sprintf("127.0.0.1:%d", socksPort), "http://"+httpAddr+"/baseline")
	if got := string(body); got != expectedBody {
		t.Fatalf("unexpected body via tunnel: got %q want %q", got, expectedBody)
	}
}

// ---------------------------------------------------------------------------
// Fixture rendering
// ---------------------------------------------------------------------------

type fixtureParams struct {
	TunnelPort int
	SocksPort  int
	Iface      string
	RouterMAC  string
	SharedKey  string
}

// loopbackRouterMAC is a syntactically-valid placeholder; the loopback path has
// no real gateway, but the config validator demands a parseable MAC.
const loopbackRouterMAC = "02:00:00:00:00:00"

func renderFixture(t *testing.T, name, dst string, p fixtureParams) string {
	t.Helper()
	src := filepath.Join("fixtures", name)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	tmpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		t.Fatalf("parse fixture %s: %v", src, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		t.Fatalf("execute fixture %s: %v", src, err)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write rendered fixture %s: %v", dst, err)
	}
	return dst
}

func lookupTestIface() string {
	if v := os.Getenv("CTUN_TEST_IFACE"); v != "" {
		return v
	}
	if runtime.GOOS == "linux" {
		return "lo"
	}
	return "lo0"
}

func newSharedKey(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

// allocLoopbackPorts probes the loopback for two free TCP ports and returns
// them. We use net.Listen on 127.0.0.1:0 to ask the kernel for an unused port,
// then close immediately. There is an inherent race vs. another listener
// snatching the port between close and the subprocess binding, but on a quiet
// loopback the race is negligible. Hardcoded ports (the original suggestion in
// the task brief) would collide on a busy developer machine, so we prefer the
// probe.
func allocLoopbackPorts(t *testing.T) (tunnel, socks int) {
	t.Helper()
	tunnel = grabFreeLoopbackPort(t)
	socks = grabFreeLoopbackPort(t)
	if tunnel == socks {
		// Astronomically unlikely with kernel-assigned ports, but guard anyway.
		t.Fatalf("port allocator returned duplicate port %d", tunnel)
	}
	return tunnel, socks
}

func grabFreeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not allocate a free loopback port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close port probe: %v", err)
	}
	return port
}

func tcpPortListening(host string, port int) bool {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ---------------------------------------------------------------------------
// HTTP test server
// ---------------------------------------------------------------------------

func startTestHTTPServer(t *testing.T, body string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/baseline", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test http: %v", err)
	}
	go func() {
		_ = srv.Serve(l)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return l.Addr().String()
}

// ---------------------------------------------------------------------------
// Subprocess management
// ---------------------------------------------------------------------------

// startCtun launches `ctun run -c <cfg>` and arranges for graceful shutdown
// via SIGTERM at the end of the test. It returns a buffer accumulating both
// stdout and stderr of the subprocess, which we surface in failure diagnostics.
func startCtun(t *testing.T, bin, cfg, role string) *syncBuf {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "run", "-c", cfg)
	cmd.SysProcAttr = newProcAttr()
	logBuf := newSyncBuf()
	cmd.Stdout = logBuf
	cmd.Stderr = logBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start ctun %s: %v", role, err)
	}

	// We don't share `cancel` because we want SIGTERM (not SIGKILL) for the
	// firewall/pcap cleanup paths inside ctun. The CommandContext is only a
	// belt-and-braces hard kill if SIGTERM is ignored.
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()

	t.Cleanup(func() {
		// Polite SIGTERM first; cancel-via-context as a forceful fallback.
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case err := <-doneCh:
			if err != nil && !isExpectedExitErr(err) {
				t.Logf("ctun %s exited with: %v\n----- %s output -----\n%s", role, err, role, logBuf.String())
			}
		case <-time.After(5 * time.Second):
			t.Logf("ctun %s did not exit on SIGTERM after 5s; forcing kill", role)
			cancel()
			select {
			case <-doneCh:
			case <-time.After(2 * time.Second):
				t.Logf("ctun %s still running after kill; leaking subprocess", role)
			}
		}
		cancel()
	})
	return logBuf
}

func isExpectedExitErr(err error) bool {
	var ee *exec.ExitError
	if !errorsAs(err, &ee) {
		return false
	}
	// SIGTERM exits with a non-zero status; we treat that as expected.
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() && (ws.Signal() == syscall.SIGTERM || ws.Signal() == syscall.SIGKILL) {
			return true
		}
	}
	return false
}

// errorsAs is a tiny indirection to keep the import list lean — equivalent to
// errors.As but avoids adding the import for one call site. Replace with the
// stdlib version if more call sites appear.
func errorsAs(err error, target **exec.ExitError) bool {
	if err == nil {
		return false
	}
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// waitFor polls cond until it returns true or timeout elapses. On timeout the
// subprocess log is included in the failure message.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool, logBuf *syncBuf) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s after %s\n----- subprocess output -----\n%s", what, timeout, logBuf.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 driver
// ---------------------------------------------------------------------------

func doHTTPThroughSOCKS5(t *testing.T, socksAddr, target string) []byte {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build SOCKS5 dialer for %s: %v", socksAddr, err)
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s via SOCKS5 %s: %v", target, socksAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Binary build (cached across subtests, rebuilt per test invocation)
// ---------------------------------------------------------------------------

var (
	binBuildOnce sync.Once
	binBuildPath string
	binBuildErr  error
)

func buildCtunBinary(t *testing.T) string {
	t.Helper()
	binBuildOnce.Do(func() {
		repoRoot, err := findRepoRoot()
		if err != nil {
			binBuildErr = err
			return
		}
		// Place the binary in the build cache dir so it doesn't pollute the
		// repo. The OS will reap it on its own schedule; we don't need it
		// past the test process lifetime.
		tmp, err := os.MkdirTemp("", "ctun-itest-bin-*")
		if err != nil {
			binBuildErr = err
			return
		}
		out := filepath.Join(tmp, "ctun")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = repoRoot
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			binBuildErr = fmt.Errorf("go build ctun: %v\n%s", err, stderr.String())
			return
		}
		binBuildPath = out
	})
	if binBuildErr != nil {
		t.Fatalf("build ctun: %v", binBuildErr)
	}
	return binBuildPath
}

// findRepoRoot walks up from the test file until it finds go.mod.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// syncBuf is a goroutine-safe buffer used to accumulate subprocess output.
// http.Server / exec.Cmd write from background goroutines; a bare bytes.Buffer
// would race.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSyncBuf() *syncBuf { return &syncBuf{} }

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	// Trim trailing whitespace so failure messages stay compact.
	return strings.TrimRight(s, "\n")
}
