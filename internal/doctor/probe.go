// Package doctor runs pre-flight diagnostics for BUAAConnect.
package doctor

import (
	"context"
	"net"
	"os"
	"os/exec"
	"time"
)

// Prober abstracts OS-level inspection so tests can inject canned output.
type Prober interface {
	// Exists returns whether path exists.
	Exists(path string) bool
	// UID returns the current effective user ID.
	UID() int
	// HasCap returns whether the process has the named capability.
	HasCap(cap string) bool
	// ReadFile returns the file contents or an error.
	ReadFile(path string) (string, error)
	// Exec runs a command with a timeout and returns stdout/stderr.
	Exec(name string, args ...string) (string, error)
	// ListenCheck attempts to bind to the address to detect port conflicts.
	ListenCheck(network, address string) error
}

// ExecProber is the default Prober implementation using the real OS.
type ExecProber struct{}

func (ExecProber) Exists(path string) bool {
	_, err := exec.LookPath(path)
	if err == nil {
		return true
	}
	_, err = os.Stat(path)
	return err == nil
}

func (ExecProber) UID() int {
	return os.Geteuid()
}

func (ExecProber) HasCap(cap string) bool {
	return hasLinuxCap(cap)
}

func (ExecProber) ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}

func (ExecProber) Exec(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (ExecProber) ListenCheck(network, address string) error {
	switch network {
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	default:
		ln, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		_ = ln.Close()
		return nil
	}
}
