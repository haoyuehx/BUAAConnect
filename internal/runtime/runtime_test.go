package runtime

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestManagerSaveAndLoad(t *testing.T) {
	m := testManager(t)
	state := &State{
		PID:      os.Getpid(),
		Profile:  "school",
		Protocol: "easyconnect",
		Server:   "vpn.buaa.edu.cn",
		Phase:    PhaseStarting,
	}
	if err := m.Save(state); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(m.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state file mode = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profile != "school" || loaded.Server != "vpn.buaa.edu.cn" {
		t.Fatalf("loaded state mismatch: %+v", loaded)
	}
	if loaded.StartedAt.IsZero() || loaded.UpdatedAt.IsZero() {
		t.Fatal("expected started/updated timestamps")
	}
}

func TestLoadNoState(t *testing.T) {
	m := testManager(t)
	if _, err := m.Load(); !IsNoState(err) {
		t.Fatalf("expected ErrNoState, got %v", err)
	}
}

func TestIsSecretField(t *testing.T) {
	secretKeys := []string{"password", "twf_id", "sid", "sign_key", "totp_secret"}
	for _, k := range secretKeys {
		if !IsSecretField(k) {
			t.Fatalf("expected %q to be secret", k)
		}
	}
	if IsSecretField("server_address") {
		t.Fatal("server_address should not be secret")
	}
}

func TestStateContainsNoSecret(t *testing.T) {
	m := testManager(t)
	state := &State{
		PID:      os.Getpid(),
		Profile:  "act",
		Protocol: "easyconnect",
		Server:   "vpn.act.buaa.edu.cn",
		Phase:    PhaseConnected,
	}
	if err := m.Save(state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(m.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"password", "token", "twfid", "TWFID"} {
		if strings.Contains(strings.ToLower(string(data)), secret) {
			t.Fatalf("state file contains possible secret %q", secret)
		}
	}
}

func TestFindInstanceStale(t *testing.T) {
	m := testManager(t)
	state := &State{
		PID:              999999,
		ProcessStartTime: 1,
		CmdLine:          "buaaconnect",
		Profile:          "school",
		Protocol:         "easyconnect",
		Server:           "vpn.buaa.edu.cn",
		Phase:            PhaseConnected,
	}
	if err := m.Save(state); err != nil {
		t.Fatal(err)
	}
	status, err := m.FindInstance()
	if err != nil {
		t.Fatal(err)
	}
	if status == nil {
		t.Fatal("expected stale status")
	}
	if status.Running || status.Owned || !status.Stale {
		t.Fatalf("unexpected status: running=%v owned=%v stale=%v", status.Running, status.Owned, status.Stale)
	}
}

func TestAcquireRefusesDuplicate(t *testing.T) {
	m := testManager(t)
	if _, err := m.Acquire("school", "easyconnect", "vpn.buaa.edu.cn"); err != nil {
		t.Fatal(err)
	}
	_, err := m.Acquire("act", "easyconnect", "vpn.act.buaa.edu.cn")
	if err == nil {
		t.Fatal("expected duplicate instance error")
	}
	if !strings.Contains(err.Error(), "another instance") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAcquireCleansStale(t *testing.T) {
	m := testManager(t)
	state := &State{
		PID:              999999,
		ProcessStartTime: 1,
		CmdLine:          "buaaconnect",
		Profile:          "school",
		Protocol:         "easyconnect",
		Server:           "vpn.buaa.edu.cn",
		Phase:            PhaseConnected,
	}
	if err := m.Save(state); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Acquire("act", "easyconnect", "vpn.act.buaa.edu.cn"); err != nil {
		t.Fatal(err)
	}
	loaded, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profile != "act" {
		t.Fatalf("expected act profile after stale cleanup, got %q", loaded.Profile)
	}
}

func TestUpdatePhase(t *testing.T) {
	m := testManager(t)
	if _, err := m.Acquire("school", "easyconnect", "vpn.buaa.edu.cn"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdatePhase(PhaseConnected, map[string]string{
		"auth_status":    "success",
		"tunnel_status":  "up",
		"tun_interface":  "buaa-school",
		"client_ip":      "10.10.0.2",
		"last_error":     "",
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase != PhaseConnected || loaded.AuthStatus != "success" || loaded.TunInterface != "buaa-school" {
		t.Fatalf("unexpected state: %+v", loaded)
	}
}

func TestStatusTextWithoutProbe(t *testing.T) {
	m := testManager(t)
	if _, err := m.Acquire("school", "easyconnect", "vpn.buaa.edu.cn"); err != nil {
		t.Fatal(err)
	}
	text, err := m.StatusText("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Process: running") {
		t.Fatalf("status text missing running process: %s", text)
	}
	want := "Target connectivity: not tested (use --probe <host:port> to verify)"
	if !strings.Contains(text, want) {
		t.Fatalf("status text missing probe guidance: %s", text)
	}
}

func TestDisconnectNoInstance(t *testing.T) {
	m := testManager(t)
	err := m.Disconnect(time.Second)
	if err == nil {
		t.Fatal("expected error for missing instance")
	}
}

func TestCleanupStale(t *testing.T) {
	m := testManager(t)
	state := &State{
		PID:              999999,
		ProcessStartTime: 1,
		CmdLine:          "buaaconnect",
		Profile:          "school",
		Protocol:         "easyconnect",
		Server:           "vpn.buaa.edu.cn",
		Phase:            PhaseConnected,
	}
	if err := m.Save(state); err != nil {
		t.Fatal(err)
	}
	if err := m.CleanupStale(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(); !IsNoState(err) {
		t.Fatal("expected state to be removed")
	}
}

func IsNoState(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrNoState
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
