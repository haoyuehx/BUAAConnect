package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// InstanceStatus describes a discovered BUAAConnect process.
type InstanceStatus struct {
	State   *State
	Running bool
	Owned   bool
	Stale   bool
}

// FindInstance loads the persisted state and verifies whether the recorded
// PID still belongs to this program. It returns a stale state with Stale=true
// when the process is gone or the PID has been reused by another program.
func (m *Manager) FindInstance() (*InstanceStatus, error) {
	state, err := m.Load()
	if err != nil {
		if errors.Is(err, ErrNoState) {
			return nil, nil
		}
		return nil, err
	}
	running := IsSameProgram(state.PID, state.ProcessStartTime, state.CmdLine)
	return &InstanceStatus{
		State:   state,
		Running: running,
		Owned:   running,
		Stale:   !running,
	}, nil
}

// CleanupStale removes the state file when no live instance owns it.
func (m *Manager) CleanupStale() error {
	status, err := m.FindInstance()
	if err != nil {
		return err
	}
	if status == nil {
		return nil
	}
	if status.Stale {
		return m.Remove()
	}
	return fmt.Errorf("instance is still running (pid %d)", status.State.PID)
}

// Acquire checks for an existing live instance and writes an initial state
// for the current process. It refuses to start when another live instance is
// detected.
func (m *Manager) Acquire(profile, protocol, server string) (*State, error) {
	status, err := m.FindInstance()
	if err != nil {
		return nil, err
	}
	if status != nil && status.Running {
		return nil, fmt.Errorf("another instance is already running (pid %d, profile %q)", status.State.PID, status.State.Profile)
	}
	if status != nil && status.Stale {
		_ = m.Remove()
	}
	self, err := SelfInfo()
	if err != nil {
		return nil, fmt.Errorf("read self process info: %w", err)
	}
	state := &State{
		PID:              self.PID,
		ProcessStartTime: self.StartTime,
		CmdLine:          self.CmdLine,
		Profile:          profile,
		Protocol:         protocol,
		Server:           server,
		Phase:            PhaseStarting,
		AuthStatus:       "pending",
		TunnelStatus:     "pending",
		StartedAt:        time.Now(),
	}
	if err := m.Save(state); err != nil {
		return nil, err
	}
	return state, nil
}

// UpdateState runs a callback to mutate and save the persisted state.
func (m *Manager) UpdateState(fn func(s *State)) error {
	state, err := m.Load()
	if err != nil {
		return err
	}
	fn(state)
	return m.Save(state)
}

// UpdatePhase updates the persisted phase and optional status fields.
func (m *Manager) UpdatePhase(phase Phase, fields map[string]string) error {
	state, err := m.Load()
	if err != nil {
		return err
	}
	state.Phase = phase
	for k, v := range fields {
		switch k {
		case "auth_status":
			state.AuthStatus = v
		case "tunnel_status":
			state.TunnelStatus = v
		case "tun_interface":
			state.TunInterface = v
		case "client_ip":
			state.ClientIP = v
		case "underlay_interface":
			state.UnderlayInterface = v
		case "last_error":
			state.LastError = v
		case "system_dns_mode":
			state.SystemDNSMode = v
		case "socks_bind":
			state.SocksBind = v
		case "http_bind":
			state.HTTPBind = v
		}
	}
	return m.Save(state)
}

// StatusText returns a human-readable summary of the instance status.
func (m *Manager) StatusText(probeTarget string) (string, error) {
	status, err := m.FindInstance()
	if err != nil {
		return "", err
	}
	if status == nil {
		return "No BUAAConnect instance is recorded.", nil
	}
	s := status.State
	var b string
	if status.Running {
		b = fmt.Sprintf("Process: running (pid %d)\n", s.PID)
	} else {
		b = fmt.Sprintf("Process: not running (stale pid %d)\n", s.PID)
	}
	b += fmt.Sprintf("Profile: %s\n", s.Profile)
	b += fmt.Sprintf("Server:  %s (%s)\n", s.Server, s.Protocol)
	b += fmt.Sprintf("Phase:   %s\n", s.Phase)
	b += fmt.Sprintf("Auth:    %s\n", s.AuthStatus)
	b += fmt.Sprintf("Tunnel:  %s\n", s.TunnelStatus)
	if s.TunInterface != "" {
		b += fmt.Sprintf("TUN:     %s\n", s.TunInterface)
	}
	if s.ClientIP != "" {
		b += fmt.Sprintf("Client IP: %s\n", s.ClientIP)
	}
	if len(s.AddedRoutes) > 0 {
		b += fmt.Sprintf("Routes:  %d added (%s)\n", len(s.AddedRoutes), strings.Join(s.AddedRoutes, ", "))
	}
	if len(s.DNSServers) > 0 {
		b += fmt.Sprintf("DNS:     %s (mode: %s)\n", strings.Join(s.DNSServers, ", "), s.SystemDNSMode)
	}
	if s.SocksBind != "" {
		b += fmt.Sprintf("SOCKS:   %s\n", s.SocksBind)
	}
	if s.HTTPBind != "" {
		b += fmt.Sprintf("HTTP:    %s\n", s.HTTPBind)
	}
	if s.LastError != "" {
		b += fmt.Sprintf("Last error: %s\n", s.LastError)
	}

	if probeTarget != "" {
		result := probeConnectivity(probeTarget, 5*time.Second)
		if result.Err != nil {
			b += fmt.Sprintf("Target connectivity: %s (failed: %v)\n", probeTarget, result.Err)
		} else {
			b += fmt.Sprintf("Target connectivity: %s (%v)\n", probeTarget, result.Duration)
		}
	} else {
		b += "Target connectivity: not tested (use --probe <host:port> to verify)\n"
	}
	return b, nil
}

// Disconnect sends SIGTERM to the running instance after verifying ownership,
// waits for it to exit, and removes the state file.
func (m *Manager) Disconnect(timeout time.Duration) error {
	status, err := m.FindInstance()
	if err != nil {
		return err
	}
	if status == nil {
		return errors.New("no BUAAConnect instance is recorded")
	}
	if !status.Running {
		_ = m.Remove()
		return errors.New("recorded instance is not running; stale state removed")
	}
	proc, err := os.FindProcess(status.State.PID)
	if err != nil {
		_ = m.Remove()
		return fmt.Errorf("find process %d: %w", status.State.PID, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to %d: %w", status.State.PID, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := waitProcessExit(ctx, status.State.PID); err != nil {
		return fmt.Errorf("wait for process %d: %w", status.State.PID, err)
	}
	return m.Remove()
}

// DaemonOptions configures background daemon spawn.
type DaemonOptions struct {
	// Password is passed to the child via stdin when non-empty.
	Password string
	// ExtraEnv adds extra environment variables to the child.
	ExtraEnv []string
}

// StartDaemon spawns a background copy of the current executable with the
// same arguments except --daemon/-d removed. The child stderr/stdout is
// redirected to <state_dir>/buaaconnect.log (0600). If Password is set, it is
// written to the child's stdin and never exposed on the command line.
func (m *Manager) StartDaemon(args []string, opts DaemonOptions) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("determine executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--daemon" || arg == "-d" {
			continue
		}
		if strings.HasPrefix(arg, "--daemon=") {
			continue
		}
		if strings.HasPrefix(arg, "-d=") {
			continue
		}
		filtered = append(filtered, arg)
	}

	logFile, err := os.OpenFile(m.LogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open daemon log: %w", err)
	}

	cmd := exec.Command(exe, filtered...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), opts.ExtraEnv...)
	if opts.Password != "" {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			_ = logFile.Close()
			return nil, fmt.Errorf("create stdin pipe: %w", err)
		}
		go func() {
			_, _ = stdin.Write([]byte(opts.Password + "\n"))
			_ = stdin.Close()
		}()
	}
	cmd.SysProcAttr = daemonSysProcAttr()
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start daemon: %w", err)
	}
	return cmd, nil
}

// WaitForPhase polls the state file until the recorded phase reaches want,
// an error phase occurs, the process exits, or the context is cancelled.
func (m *Manager) WaitForPhase(ctx context.Context, want Phase) (*State, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			state, err := m.Load()
			if err != nil {
				if errors.Is(err, ErrNoState) {
					continue
				}
				return nil, err
			}
			if state.Phase == want {
				return state, nil
			}
			if state.Phase == PhaseError {
				return state, fmt.Errorf("instance entered error phase: %s", state.LastError)
			}
			if !IsSameProgram(state.PID, state.ProcessStartTime, state.CmdLine) {
				return nil, errors.New("daemon process exited or PID reused")
			}
		}
	}
}

func waitProcessExit(ctx context.Context, pid int) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !processExists(pid) {
				return nil
			}
		}
	}
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		_ = proc.Release()
		return true
	}
	// On Unix, Signal(0) checks existence without delivering a signal.
	err = proc.Signal(syscall.Signal(0))
	_ = proc.Release()
	return err == nil
}
