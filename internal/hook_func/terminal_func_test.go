package hook_func

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetTerminalState(t *testing.T) {
	t.Helper()
	terminalMu.Lock()
	originalBegin := terminalBegin
	originalList := terminalFuncList
	originalTimeout := terminalFuncTimeout
	terminalBegin = false
	terminalFuncList = nil
	terminalMu.Unlock()
	t.Cleanup(func() {
		terminalMu.Lock()
		terminalBegin = originalBegin
		terminalFuncList = originalList
		terminalFuncTimeout = originalTimeout
		terminalMu.Unlock()
	})
}

func TestExecTerminalFuncTimesOutHungHook(t *testing.T) {
	resetTerminalState(t)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	terminalMu.Lock()
	terminalFuncTimeout = 30 * time.Millisecond
	terminalMu.Unlock()

	RegisterTerminalFunc("hung", func(context.Context) error {
		<-release
		return nil
	})
	RegisterTerminalFunc("healthy", func(context.Context) error {
		return nil
	})

	start := time.Now()
	errs := ExecTerminalFunc(context.Background())
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("ExecTerminalFunc took %s, want it to time out quickly", elapsed)
	}
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want exactly the timeout error", errs)
	}
	if !strings.Contains(errs[0].Error(), "timed out") || !strings.Contains(errs[0].Error(), "hung") {
		t.Fatalf("error = %v, want a timeout mentioning the hook", errs[0])
	}

	// The healthy hook still ran after the stalled one.
	releaseOnce.Do(func() { close(release) })
}

func TestExecTerminalFuncHonoursCancelledContext(t *testing.T) {
	resetTerminalState(t)
	terminalMu.Lock()
	terminalFuncTimeout = time.Minute
	terminalMu.Unlock()

	RegisterTerminalFunc("blocked", func(context.Context) error {
		select {}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	errs := ExecTerminalFunc(ctx)
	if len(errs) != 1 {
		t.Fatalf("errors = %v, want one cancellation error", errs)
	}
}
