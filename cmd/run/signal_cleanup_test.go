package run

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSignalCleanup_CtxCancelInvokesCleanup verifies the wiring contract
// firewall.InstallCleanup (called from setupFirewall) provides: cancelling
// the parent context causes the registered Manager.Cleanup to fire
// asynchronously. The deferred cleanup returned from setupFirewall (which
// the caller in server.go / client.go always invokes) then provides the
// authoritative second Cleanup — so total invocations after the deferred
// cleanup runs is exactly 2.
//
// We don't actually send SIGINT in this test — Go's os/signal package
// delivers SIGINT to every process-wide handler, which would interact
// poorly with `go test`'s own signal handling. Instead we exercise the
// ctx.Done() arm of InstallCleanup's select, which has identical
// behaviour (both arms call mgr.Cleanup() then exit the goroutine).
// The SIGINT path is exercised by the per-OS firewall tests
// (linux_test.go, darwin_test.go) where the real binary is sent a
// signal.
func TestSignalCleanup_CtxCancelInvokesCleanup(t *testing.T) {
	m := withMockFirewall(t)
	cfg := newConfForTest(true, true, 9999)

	ctx, cancel := context.WithCancel(context.Background())
	cleanup, err := setupFirewall(ctx, cfg, true)
	if err != nil {
		t.Fatalf("setupFirewall: %v", err)
	}
	// Cancel the context — InstallCleanup's goroutine should fire
	// Cleanup. We then wait briefly for the goroutine to run.
	cancel()

	// Poll for the async Cleanup with a bounded timeout. The
	// InstallCleanup goroutine is plain Go scheduling, so a 1s
	// budget is generous for any healthy CI runner.
	deadline := time.Now().Add(1 * time.Second)
	for m.cleanupCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := m.cleanupCalls.Load(); got < 1 {
		t.Fatalf("ctx.Cancel should trigger Cleanup; got %d invocations", got)
	}

	// Now run the deferred cleanup the way server.go / client.go do.
	// Total Cleanup count must end at exactly 2 (one from the signal
	// goroutine, one from the deferred path). Manager.Cleanup is
	// idempotent on all three real backends, so the doubled call is
	// safe in production.
	cleanup()
	if got := m.cleanupCalls.Load(); got != 2 {
		t.Errorf("after deferred cleanup, total Cleanup count: got %d, want 2", got)
	}
}

// TestSignalCleanup_DeferOnlyPath verifies the no-signal happy path:
// when no signal arrives and the context is not cancelled until after
// the deferred cleanup runs, the Cleanup count is exactly 1 (from the
// deferred path; the InstallCleanup goroutine never fires because
// unhook tears it down first).
//
// Note: today's InstallCleanup goroutine watches ctx.Done() OR the
// signal channel; the deferred cleanup calls unhook() before mgr.Cleanup(),
// but unhook doesn't actually cancel the goroutine — it only detaches
// the signal handler. The goroutine still watches ctx.Done(). So when
// the cleanup() deferred path runs first (no signal, no ctx cancel),
// it fires mgr.Cleanup() once. After that, when the test's deferred
// cancel finally cancels ctx, the InstallCleanup goroutine wakes up
// and fires mgr.Cleanup() a second time. That's documented behaviour
// — Manager.Cleanup is idempotent — but it means the assertion below
// must allow for either 1 or 2 calls depending on goroutine timing.
//
// The important invariant: at least one Cleanup happens, and Cleanup
// never panics on the second invocation.
func TestSignalCleanup_DeferOnlyPath(t *testing.T) {
	m := withMockFirewall(t)
	cfg := newConfForTest(true, true, 9999)

	ctx, cancel := context.WithCancel(context.Background())
	cleanup, err := setupFirewall(ctx, cfg, true)
	if err != nil {
		t.Fatalf("setupFirewall: %v", err)
	}

	// Simulate the workload exiting cleanly, then the deferred cleanup
	// running, then ctx being cancelled.
	cleanup()
	cancel()

	// Give the InstallCleanup goroutine a beat to react to the
	// ctx.Done() that arrives after cleanup(). Manager.Cleanup is
	// idempotent so this is harmless in production.
	time.Sleep(50 * time.Millisecond)

	calls := m.cleanupCalls.Load()
	if calls < 1 || calls > 2 {
		t.Errorf("deferred-only path: got %d Cleanup calls, want 1 or 2 (idempotent)", calls)
	}
}

// TestRunWithFirewall_CleanReturnInvokesCleanup verifies that the
// panic-aware wrapper runs cleanup on the normal return path. This
// is the dominant case: ctun shuts down cleanly via SIGTERM, the
// inner workload returns, and the deferred cleanup must still fire.
func TestRunWithFirewall_CleanReturnInvokesCleanup(t *testing.T) {
	var cleanupCalls int
	cleanup := func() { cleanupCalls++ }

	workloadCalled := false
	runWithFirewall(cleanup, func() { workloadCalled = true })

	if !workloadCalled {
		t.Fatal("workload was not invoked")
	}
	if cleanupCalls != 1 {
		t.Errorf("cleanup invocations on clean return: got %d, want 1", cleanupCalls)
	}
}

// TestRunWithFirewall_PanicInvokesCleanupAndRepanics verifies the
// panic-recovery contract: when the workload panics, cleanup must fire
// AND the panic must propagate so the runtime's default behaviour
// (stack trace, non-zero exit) is preserved. A swallowed panic would
// hide bugs.
func TestRunWithFirewall_PanicInvokesCleanupAndRepanics(t *testing.T) {
	var cleanupCalls int
	cleanup := func() { cleanupCalls++ }

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic to propagate; runWithFirewall swallowed it")
		}
		if cleanupCalls != 1 {
			t.Errorf("cleanup invocations after panic: got %d, want 1", cleanupCalls)
		}
		// The panic value must be the original — runWithFirewall must
		// not wrap or replace it.
		err, ok := r.(error)
		if !ok {
			t.Fatalf("panic value type: got %T, want error", r)
		}
		if !errors.Is(err, errSentinel) {
			t.Errorf("panic value: got %v, want sentinel %v", err, errSentinel)
		}
	}()

	runWithFirewall(cleanup, func() {
		panic(errSentinel)
	})
}

// errSentinel is a stable panic value the test asserts against. Defined
// at package scope (not inside the test func) so errors.Is can compare
// against the same identity even after runWithFirewall re-panics.
var errSentinel = errors.New("simulated workload panic")
