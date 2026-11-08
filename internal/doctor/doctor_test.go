package doctor

import (
	"fmt"
	"strings"
	"testing"
)

type mockProber struct {
	exists   map[string]bool
	uid      int
	caps     map[string]bool
	files    map[string]string
	commands map[string]string
	listenOK map[string]bool
}

func newMockProber() *mockProber {
	return &mockProber{
		exists:   map[string]bool{},
		caps:     map[string]bool{},
		files:    map[string]string{},
		commands: map[string]string{},
		listenOK: map[string]bool{},
	}
}

func (m *mockProber) Exists(path string) bool { return m.exists[path] }
func (m *mockProber) UID() int                { return m.uid }
func (m *mockProber) HasCap(cap string) bool  { return m.caps[cap] }
func (m *mockProber) ReadFile(path string) (string, error) {
	if v, ok := m.files[path]; ok {
		return v, nil
	}
	return "", fmt.Errorf("not found")
}
func (m *mockProber) Exec(name string, args ...string) (string, error) {
	key := name + " " + joinArgs(args)
	if v, ok := m.commands[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("command not mocked")
}
func (m *mockProber) ListenCheck(network, address string) error {
	if m.listenOK[address] {
		return nil
	}
	return fmt.Errorf("address %s in use", address)
}

func joinArgs(args []string) string {
	return strings.Join(args, " ")
}

func TestCheckPermissionsRoot(t *testing.T) {
	p := newMockProber()
	p.uid = 0
	p.exists["/dev/net/tun"] = true
	p.caps["cap_net_admin"] = true

	results := checkPermissions(p)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.OK {
			t.Fatalf("unexpected failure: %s", r.Detail)
		}
	}
}

func TestCheckPermissionsNoTUN(t *testing.T) {
	p := newMockProber()
	p.uid = 1000
	results := checkPermissions(p)
	var foundError bool
	for _, r := range results {
		if r.Check == "permissions" && r.Level == "error" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("expected error for missing /dev/net/tun: %+v", results)
	}
}

func TestCheckDNSLocalhost(t *testing.T) {
	p := newMockProber()
	p.exists["resolvectl"] = true
	p.files["/etc/resolv.conf"] = "nameserver 127.0.0.1\n"
	results := checkDNS(p)
	var foundWarn bool
	for _, r := range results {
		if r.Check == "dns" && r.Level == "warn" && strings.Contains(r.Detail, "localhost") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected localhost warning: %+v", results)
	}
}

func TestCheckPortsConflict(t *testing.T) {
	p := newMockProber()
	p.listenOK["127.0.0.1:11081"] = true
	cfg := Config{
		SocksBind: "127.0.0.1:11080",
		HTTPBind:  "127.0.0.1:11081",
	}
	results := checkPorts(p, cfg)
	var conflict, ok bool
	for _, r := range results {
		if r.Check != "ports" {
			continue
		}
		if !r.OK {
			conflict = true
		} else {
			ok = true
		}
	}
	if !conflict || !ok {
		t.Fatalf("expected one conflict and one ok: %+v", results)
	}
}

func TestCheckPortsRunningInstance(t *testing.T) {
	p := newMockProber()
	p.listenOK["127.0.0.1:11081"] = true
	cfg := Config{
		SocksBind:       "127.0.0.1:11080",
		HTTPBind:        "127.0.0.1:11081",
		InstanceRunning: true,
	}
	results := checkPorts(p, cfg)
	var warn bool
	for _, r := range results {
		if r.Check == "ports" && !r.OK && r.Level == "warn" && strings.Contains(r.Detail, "running BUAAConnect instance") {
			warn = true
		}
	}
	if !warn {
		t.Fatalf("expected warn for port in use by running instance: %+v", results)
	}
}

func TestCheckTUNOwnInterface(t *testing.T) {
	p := newMockProber()
	p.commands["ip link show up"] = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
10: buaa-school: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400 ...`
	results := checkTUNInterfaces(p, "buaa-school")
	var foundOwn bool
	for _, r := range results {
		if r.Check == "tun" && strings.Contains(r.Detail, "buaa-school") {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatalf("expected own TUN detection: %+v", results)
	}
}

func TestCheckTUNExternal(t *testing.T) {
	p := newMockProber()
	p.commands["ip link show up"] = `1: lo: <LOOPBACK,UP,LOWER_UP> ...
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> ...`
	results := checkTUNInterfaces(p, "buaa-school")
	var foundExternal bool
	for _, r := range results {
		if r.Check == "tun" && strings.Contains(r.Detail, "tun0") {
			foundExternal = true
		}
	}
	if !foundExternal {
		t.Fatalf("expected external tun0 detection: %+v", results)
	}
}

func TestCheckTUNUppercaseMeta(t *testing.T) {
	p := newMockProber()
	p.commands["ip link show up"] = `1: lo: <LOOPBACK,UP,LOWER_UP> ...
5: Meta: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> ...`
	results := checkTUNInterfaces(p, "buaa-school")
	var foundExternal bool
	for _, r := range results {
		if r.Check == "tun" && strings.Contains(r.Detail, "Meta") {
			foundExternal = true
		}
	}
	if !foundExternal {
		t.Fatalf("expected uppercase Meta interface detection: %+v", results)
	}
}

func TestDetectClashOff(t *testing.T) {
	p := newMockProber()
	state, evidence := DetectClash(p, "buaa-school")
	if state != ClashOff {
		t.Fatalf("expected ClashOff, got %s", state)
	}
	if len(evidence) == 0 {
		t.Fatal("expected evidence for off state")
	}
}

func TestDetectClashProxy(t *testing.T) {
	p := newMockProber()
	p.commands["pgrep -a clash"] = "1234 clash -d /etc/clash\n"
	state, evidence := DetectClash(p, "buaa-school")
	if state != ClashProxy {
		t.Fatalf("expected ClashProxy, got %s", state)
	}
	if len(evidence) == 0 {
		t.Fatal("expected evidence")
	}
}

func TestDetectClashTUN(t *testing.T) {
	p := newMockProber()
	p.commands["pgrep -a mihomo"] = "5678 mihomo\n"
	p.commands["ip link show up"] = "5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> ...\n"
	p.commands["ip route show"] = "198.18.0.0/16 dev tun0 scope link\n"
	p.commands["ip rule show"] = "32765: not from all fwmark 0x1 lookup 2022\n"
	state, evidence := DetectClash(p, "buaa-school")
	if state != ClashTUN {
		t.Fatalf("expected ClashTUN, got %s", state)
	}
	var foundFakeIP bool
	for _, e := range evidence {
		if strings.Contains(e, "198.18.0.0/16") {
			foundFakeIP = true
		}
	}
	if !foundFakeIP {
		t.Fatalf("expected fake-ip evidence: %v", evidence)
	}
}

func TestDetectClashIgnoresOwnTUN(t *testing.T) {
	p := newMockProber()
	p.commands["ip link show up"] = "10: buaa-school: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> ...\n"
	p.commands["ip route show"] = "default dev buaa-school scope link\n"
	p.commands["ip rule show"] = "32764: from all lookup 100\n"
	state, evidence := DetectClash(p, "buaa-school")
	if state != ClashOff {
		t.Fatalf("expected ClashOff when only own TUN is present, got %s (evidence=%v)", state, evidence)
	}
}

func TestDetectClashExternalTUNWithoutProcess(t *testing.T) {
	p := newMockProber()
	p.commands["ip link show up"] = "5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> ...\n"
	p.commands["ip route show"] = "default dev tun0 scope link\n"
	p.commands["ip rule show"] = "32764: from all lookup 100\n"
	state, evidence := DetectClash(p, "buaa-school")
	if state != ClashTUN {
		t.Fatalf("expected ClashTUN for external tun0, got %s", state)
	}
	for _, e := range evidence {
		if strings.Contains(e, "buaa-school") {
			t.Fatalf("own TUN should not appear in clash evidence: %v", evidence)
		}
	}
}

func TestRunReportOK(t *testing.T) {
	p := newMockProber()
	p.uid = 0
	p.exists["/dev/net/tun"] = true
	p.exists["resolvectl"] = true
	p.caps["cap_net_admin"] = true
	p.files["/etc/resolv.conf"] = "nameserver 223.5.5.5\n"
	p.commands["ip link show up"] = "1: lo: <LOOPBACK,UP> ...\n"
	p.listenOK["127.0.0.1:11080"] = true
	cfg := Config{SocksBind: "127.0.0.1:11080"}
	report := Run(p, cfg)
	if !report.OK {
		for _, r := range report.Results {
			t.Logf("%s: %s", r.Check, r.Detail)
		}
		t.Fatal("expected report to be OK")
	}
}

func TestFormatReport(t *testing.T) {
	r := &Report{
		Results: []Result{
			{Check: "permissions", OK: true, Level: "info", Detail: "root"},
			{Check: "dns", OK: false, Level: "warn", Detail: "localhost", Advice: "check resolv.conf"},
		},
		OK: false,
	}
	s := FormatReport(r)
	if !strings.Contains(s, "root") || !strings.Contains(s, "check resolv.conf") {
		t.Fatalf("unexpected formatted report: %s", s)
	}
}
