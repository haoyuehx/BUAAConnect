package hook_func

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

type TerminalFunc func(ctx context.Context) error
type TerminalItem struct {
	f    TerminalFunc
	name string
}

var terminalFuncList []TerminalItem

var terminalBegin = false
var terminalMu sync.Mutex

// terminalFuncTimeout bounds each cleanup hook. A stuck hook (for example a
// blocked route/DNS command) must not prevent the remaining cleanup hooks
// from running during shutdown. Tests may lower it.
var terminalFuncTimeout = 5 * time.Second

func RegisterTerminalFunc(execName string, fun TerminalFunc) {
	terminalMu.Lock()
	defer terminalMu.Unlock()

	if terminalBegin {
		log.Println("Terminal already started, skip registering func:", execName)
		return
	}

	terminalFuncList = append(terminalFuncList, TerminalItem{
		f:    fun,
		name: execName,
	})
	log.Println("Register func on terminal:", execName)
}

func ExecTerminalFunc(ctx context.Context) []error {
	terminalMu.Lock()
	if terminalBegin {
		terminalMu.Unlock()
		return nil
	}
	terminalBegin = true
	funcList := append([]TerminalItem(nil), terminalFuncList...)
	terminalMu.Unlock()

	var errList []error
	for _, item := range funcList {
		log.Println("Exec func on terminal:", item.name)
		if err := runTerminalFunc(ctx, item); err != nil {
			errList = append(errList, err)
			log.Println("Exec func on terminal ", item.name, "failed:", err)
		} else {
			log.Println("Exec func on terminal ", item.name, "success")
		}
	}
	return errList
}

func runTerminalFunc(ctx context.Context, item TerminalItem) error {
	timeout := terminalFuncTimeout
	if timeout <= 0 {
		return item.f(ctx)
	}

	done := make(chan error, 1)
	go func() {
		done <- item.f(ctx)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("terminal func %q timed out after %s", item.name, timeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func IsTerminal() bool {
	terminalMu.Lock()
	defer terminalMu.Unlock()

	return terminalBegin
}
