// Package runtime manages BUAAConnect runtime state, process ownership,
// duplicate-instance prevention, and daemon lifecycle.
package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Phase represents the high-level lifecycle phase of a BUAAConnect instance.
type Phase string

const (
	PhaseStarting       Phase = "starting"
	PhaseAuthenticating Phase = "authenticating"
	PhaseConnected      Phase = "connected"
	PhaseReconnecting   Phase = "reconnecting"
	PhaseStopping       Phase = "stopping"
	PhaseError          Phase = "error"
)

// State is the persisted runtime state. It must never contain secrets
// such as passwords, tokens, or TWFID.
type State struct {
	PID               int       `json:"pid"`
	ProcessStartTime  uint64    `json:"process_start_time"`
	CmdLine           string    `json:"cmd_line"`
	Profile           string    `json:"profile"`
	Protocol          string    `json:"protocol"`
	Server            string    `json:"server"`
	Phase             Phase     `json:"phase"`
	AuthStatus        string    `json:"auth_status"`
	TunnelStatus      string    `json:"tunnel_status"`
	TunInterface      string    `json:"tun_interface"`
	ClientIP          string    `json:"client_ip"`
	UnderlayInterface string    `json:"underlay_interface"`
	AddedRoutes       []string  `json:"added_routes"`
	DNSServers        []string  `json:"dns_servers"`
	SystemDNSMode     string    `json:"system_dns_mode"`
	SocksBind         string    `json:"socks_bind"`
	HTTPBind          string    `json:"http_bind"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastError         string    `json:"last_error"`
}

// Manager provides access to the runtime state directory and state file.
type Manager struct {
	StateDir string
}

// NewManager creates a Manager using the given state directory.
// If stateDir is empty, it defaults to $HOME/.local/share/buaaconnect.
func NewManager(stateDir string) (*Manager, error) {
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("determine user home: %w", err)
		}
		stateDir = filepath.Join(home, ".local", "share", "buaaconnect")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir %q: %w", stateDir, err)
	}
	return &Manager{StateDir: stateDir}, nil
}

// StatePath returns the path to state.json.
func (m *Manager) StatePath() string {
	return filepath.Join(m.StateDir, "state.json")
}

// LogPath returns the path to buaaconnect.log.
func (m *Manager) LogPath() string {
	return filepath.Join(m.StateDir, "buaaconnect.log")
}

// Load reads and parses the state file. It returns ErrNoState if the file
// does not exist.
func (m *Manager) Load() (*State, error) {
	data, err := os.ReadFile(m.StatePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoState
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}
	return &s, nil
}

// Save writes the state file atomically with mode 0600.
func (m *Manager) Save(s *State) error {
	if s == nil {
		return errors.New("nil state")
	}
	s.UpdatedAt = time.Now()
	if s.StartedAt.IsZero() {
		s.StartedAt = s.UpdatedAt
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')
	tmp := m.StatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write state temp file: %w", err)
	}
	if err := os.Rename(tmp, m.StatePath()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}

// Remove deletes the state file if it exists.
func (m *Manager) Remove() error {
	err := os.Remove(m.StatePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ErrNoState indicates that no state file exists.
var ErrNoState = errors.New("no state file found")

// IsSecretField reports whether a config field name holds a credential.
func IsSecretField(key string) bool {
	switch key {
	case "password", "cert_password", "socks_passwd", "twf_id", "sid",
		"device_id", "sign_key", "client_data_file", "resource_file",
		"totp_secret", "oauth2_code", "cas_ticket":
		return true
	default:
		return false
	}
}
