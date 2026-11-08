package doctor

import (
	"fmt"
	"net"
	"strings"
)

// Config holds the settings to diagnose.
type Config struct {
	SocksBind       string
	HTTPBind        string
	DNSServerBind   string
	PortForwarding  []PortForward
	TUNInterface    string
	InstanceRunning bool
}

type PortForward struct {
	NetworkType   string
	BindAddress   string
	RemoteAddress string
}

// Result is one diagnostic finding.
type Result struct {
	Check  string
	OK     bool
	Level  string // info, warn, error
	Detail string
	Advice string
}

// Report contains all findings plus a summary.
type Report struct {
	Results []Result
	OK      bool
}

// Run executes all diagnostic checks and returns a report.
func Run(prober Prober, cfg Config) *Report {
	var results []Result
	results = append(results, checkPermissions(prober)...)
	results = append(results, checkDNS(prober)...)
	results = append(results, checkPorts(prober, cfg)...)
	results = append(results, checkTUNInterfaces(prober, cfg.TUNInterface)...)
	results = append(results, checkClash(prober, cfg.TUNInterface)...)

	ok := true
	for _, r := range results {
		if r.Level == "error" {
			ok = false
			break
		}
	}
	return &Report{Results: results, OK: ok}
}

func checkPermissions(prober Prober) []Result {
	var results []Result
	if prober.UID() == 0 {
		results = append(results, Result{
			Check:  "permissions",
			OK:     true,
			Level:  "info",
			Detail: "Running as root.",
		})
	} else {
		results = append(results, Result{
			Check:  "permissions",
			OK:     false,
			Level:  "warn",
			Detail: fmt.Sprintf("Running as UID %d (not root).", prober.UID()),
			Advice: "Run with sudo or grant CAP_NET_ADMIN for TUN mode.",
		})
	}

	if prober.Exists("/dev/net/tun") {
		results = append(results, Result{
			Check:  "permissions",
			OK:     true,
			Level:  "info",
			Detail: "/dev/net/tun exists.",
		})
	} else {
		results = append(results, Result{
			Check:  "permissions",
			OK:     false,
			Level:  "error",
			Detail: "/dev/net/tun does not exist.",
			Advice: "Load the tun module or run on a system with TUN support.",
		})
	}

	if prober.HasCap("cap_net_admin") {
		results = append(results, Result{
			Check:  "permissions",
			OK:     true,
			Level:  "info",
			Detail: "Process has CAP_NET_ADMIN.",
		})
	} else if prober.UID() != 0 {
		results = append(results, Result{
			Check:  "permissions",
			OK:     false,
			Level:  "warn",
			Detail: "Process lacks CAP_NET_ADMIN.",
			Advice: "Use sudo or setcap cap_net_admin+eip on the binary.",
		})
	}
	return results
}

func checkDNS(prober Prober) []Result {
	var results []Result
	if prober.Exists("resolvectl") {
		results = append(results, Result{
			Check:  "dns",
			OK:     true,
			Level:  "info",
			Detail: "resolvectl is available.",
		})
	} else if prober.Exists("systemd-resolve") {
		results = append(results, Result{
			Check:  "dns",
			OK:     true,
			Level:  "info",
			Detail: "systemd-resolve is available.",
		})
	} else {
		results = append(results, Result{
			Check:  "dns",
			OK:     false,
			Level:  "warn",
			Detail: "Neither resolvectl nor systemd-resolve found.",
			Advice: "DNS hijack via resolvectl may not work; use --system-dns off or configure /etc/resolv.conf manually.",
		})
	}

	data, err := prober.ReadFile("/etc/resolv.conf")
	if err != nil {
		results = append(results, Result{
			Check:  "dns",
			OK:     false,
			Level:  "warn",
			Detail: "Unable to read /etc/resolv.conf.",
			Advice: "Check file permissions.",
		})
	} else {
		hasLocalhost := strings.Contains(data, "127.0.0.1") || strings.Contains(data, "::1")
		if hasLocalhost {
			results = append(results, Result{
				Check:  "dns",
				OK:     false,
				Level:  "warn",
				Detail: "/etc/resolv.conf points to localhost.",
				Advice: "A local DNS forwarder is active; ensure it forwards VPN domains to BUAAConnect.",
			})
		} else {
			results = append(results, Result{
				Check:  "dns",
				OK:     true,
				Level:  "info",
				Detail: "/etc/resolv.conf readable.",
			})
		}
	}
	return results
}

func checkPorts(prober Prober, cfg Config) []Result {
	var results []Result
	for _, addr := range []string{cfg.SocksBind, cfg.HTTPBind, cfg.DNSServerBind} {
		if addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			results = append(results, Result{
				Check:  "ports",
				OK:     false,
				Level:  "warn",
				Detail: fmt.Sprintf("Invalid bind address %q: %v", addr, err),
			})
			continue
		}
		if host == "" {
			host = "0.0.0.0"
		}
		checkAddr := net.JoinHostPort(host, port)
		if err := prober.ListenCheck("tcp", checkAddr); err != nil {
			level := "error"
			detail := fmt.Sprintf("Port %s is already in use (%s).", addr, err)
			advice := "Choose a different bind address or stop the conflicting service."
			if cfg.InstanceRunning {
				level = "warn"
				detail = fmt.Sprintf("Port %s is in use (possibly by running BUAAConnect instance).", addr)
				advice = "If this is the current BUAAConnect instance, no action is needed."
			}
			results = append(results, Result{
				Check:  "ports",
				OK:     false,
				Level:  level,
				Detail: detail,
				Advice: advice,
			})
		} else {
			results = append(results, Result{
				Check:  "ports",
				OK:     true,
				Level:  "info",
				Detail: fmt.Sprintf("Port %s is available.", addr),
			})
		}
	}
	for _, pf := range cfg.PortForwarding {
		if pf.BindAddress == "" {
			continue
		}
		host, port, err := net.SplitHostPort(pf.BindAddress)
		if err != nil {
			continue
		}
		if host == "" {
			host = "0.0.0.0"
		}
		checkAddr := net.JoinHostPort(host, port)
		if err := prober.ListenCheck(pf.NetworkType, checkAddr); err != nil {
			level := "error"
			detail := fmt.Sprintf("Port forwarding bind %s is already in use.", pf.BindAddress)
			advice := "Free the port or change the forwarding bind address."
			if cfg.InstanceRunning {
				level = "warn"
				detail = fmt.Sprintf("Port forwarding bind %s is in use (possibly by running BUAAConnect instance).", pf.BindAddress)
				advice = "If this is the current BUAAConnect instance, no action is needed."
			}
			results = append(results, Result{
				Check:  "ports",
				OK:     false,
				Level:  level,
				Detail: detail,
				Advice: advice,
			})
		}
	}
	return results
}

func checkTUNInterfaces(prober Prober, ownTUN string) []Result {
	var results []Result
	out, err := prober.Exec("ip", "link", "show", "up")
	if err != nil {
		results = append(results, Result{
			Check:  "tun",
			OK:     false,
			Level:  "warn",
			Detail: "Unable to list network interfaces.",
		})
		return results
	}

	lines := strings.Split(out, "\n")
	var ownFound, externalFound bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ": <") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		ifName := strings.TrimSpace(parts[1])
		if ifName == "lo" || ifName == "" {
			continue
		}
		lowerName := strings.ToLower(ifName)
		if strings.HasPrefix(lowerName, "buaa-") || strings.HasPrefix(lowerName, "buaaconnect") || ifName == ownTUN {
			ownFound = true
			results = append(results, Result{
				Check:  "tun",
				OK:     true,
				Level:  "info",
				Detail: fmt.Sprintf("Found BUAAConnect TUN interface %q.", ifName),
			})
		} else if isExternalTUNInterface(lowerName, ownTUN) {
			externalFound = true
			results = append(results, Result{
				Check:  "tun",
				OK:     false,
				Level:  "warn",
				Detail: fmt.Sprintf("Found external TUN-like interface %q.", ifName),
				Advice: "If it belongs to Clash/another VPN, ensure routes do not conflict.",
			})
		}
	}

	if ownTUN != "" && !ownFound {
		results = append(results, Result{
			Check:  "tun",
			OK:     true,
			Level:  "info",
			Detail: fmt.Sprintf("Own TUN interface %q is not currently present (expected before connection).", ownTUN),
		})
	}
	if !ownFound && !externalFound {
		results = append(results, Result{
			Check:  "tun",
			OK:     true,
			Level:  "info",
			Detail: "No TUN interfaces are currently up.",
		})
	}
	return results
}

func isExternalTUNInterface(lowerName, ownTUN string) bool {
	if strings.HasPrefix(lowerName, "meta") ||
		strings.HasPrefix(lowerName, "mihomo") ||
		strings.HasPrefix(lowerName, "clash") ||
		strings.HasPrefix(lowerName, "utun") {
		return true
	}
	if strings.HasPrefix(lowerName, "tun") && lowerName != strings.ToLower(ownTUN) {
		return true
	}
	return false
}

// ClashState represents the detected Clash coexistence state.
type ClashState string

const (
	ClashOff     ClashState = "off"
	ClashProxy   ClashState = "proxy"
	ClashTUN     ClashState = "tun"
	ClashUnknown ClashState = "unknown"
)

// DetectClash returns the detected Clash state and supporting evidence.
// ownTUN is excluded from external-TUN detection so BUAAConnect's own routes
// are not mistaken for Clash.
func DetectClash(prober Prober, ownTUN string) (ClashState, []string) {
	var evidence []string

	// Check for Clash/mihomo/Meta API or process presence.
	for _, proc := range []string{"clash", "clash-meta", "mihomo", "cfw"} {
		if out, err := prober.Exec("pgrep", "-a", proc); err == nil && strings.TrimSpace(out) != "" {
			evidence = append(evidence, fmt.Sprintf("process %q is running: %s", proc, strings.TrimSpace(out)))
		}
	}

	externalIfs := listExternalTUNInterfaces(prober, ownTUN)
	routeOut, _ := prober.Exec("ip", "route", "show")
	ruleOut, _ := prober.Exec("ip", "rule", "show")

	for _, ifName := range externalIfs {
		evidence = append(evidence, fmt.Sprintf("external TUN interface %q is up", ifName))
		if strings.Contains(routeOut, "dev "+ifName) {
			evidence = append(evidence, fmt.Sprintf("active routes via %s", ifName))
		}
		if strings.Contains(ruleOut, ifName) {
			evidence = append(evidence, fmt.Sprintf("ip rule references %s (policy routing active)", ifName))
		}
	}

	// Check for fake-ip route conflict.
	if strings.Contains(routeOut, "198.18.0.0/16") {
		evidence = append(evidence, "route for 198.18.0.0/16 exists (Clash fake-ip TUN mode)")
	}

	// Check for port 53 listeners (excluding systemd-resolved stub 127.0.0.53/54).
	for _, cmd := range [][]string{
		{"ss", "-lnp", "src", ":53"},
		{"netstat", "-lnp"},
	} {
		if out, err := prober.Exec(cmd[0], cmd[1:]...); err == nil && strings.Contains(out, ":53 ") {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, ":53 ") && !strings.Contains(line, "127.0.0.53") && !strings.Contains(line, "127.0.0.54") {
					evidence = append(evidence, fmt.Sprintf("port 53 listener detected: %s", strings.TrimSpace(line)))
					break
				}
			}
			break
		}
	}

	if len(evidence) == 0 {
		return ClashOff, []string{"no Clash/mihomo process, external TUN interface, policy route, fake-ip route, or port-53 listener detected"}
	}

	hasTUN := false
	for _, e := range evidence {
		if strings.Contains(e, "TUN interface") ||
			strings.Contains(e, "routes via") ||
			strings.Contains(e, "ip rule") ||
			strings.Contains(e, "198.18.0.0/16") ||
			strings.Contains(e, "port 53 listener") {
			hasTUN = true
			break
		}
	}
	if hasTUN {
		return ClashTUN, evidence
	}
	return ClashProxy, evidence
}

func listExternalTUNInterfaces(prober Prober, ownTUN string) []string {
	out, err := prober.Exec("ip", "link", "show", "up")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ": <") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		ifName := strings.TrimSpace(parts[1])
		if ifName == "lo" || ifName == "" {
			continue
		}
		if isExternalTUNInterface(strings.ToLower(ifName), ownTUN) {
			names = append(names, ifName)
		}
	}
	return names
}

func checkClash(prober Prober, ownTUN string) []Result {
	state, evidence := DetectClash(prober, ownTUN)
	switch state {
	case ClashOff:
		return []Result{{
			Check:  "clash",
			OK:     true,
			Level:  "info",
			Detail: "Clash appears to be off.",
		}}
	case ClashProxy:
		return []Result{{
			Check:  "clash",
			OK:     true,
			Level:  "info",
			Detail: "Clash is running in normal proxy mode.",
			Advice: "Evidence: " + strings.Join(evidence, "; ") + ". Ensure applications are routed to BUAAConnect when needed.",
		}}
	case ClashTUN:
		return []Result{{
			Check:  "clash",
			OK:     false,
			Level:  "warn",
			Detail: "Detected active external/Clash TUN routing.",
			Advice: "Evidence: " + strings.Join(evidence, "; ") + ". Stop the other TUN-based tool or adjust ip rule/routes to avoid conflicts with BUAAConnect TUN.",
		}}
	default:
		return []Result{{
			Check:  "clash",
			OK:     false,
			Level:  "warn",
			Detail: "Unable to determine Clash state.",
		}}
	}
}

// FormatReport returns a human-readable rendering of a diagnostic report.
func FormatReport(r *Report) string {
	var b strings.Builder
	for _, res := range r.Results {
		status := "OK"
		if !res.OK {
			status = strings.ToUpper(res.Level)
		}
		b.WriteString(fmt.Sprintf("[%s] %s: %s\n", status, res.Check, res.Detail))
		if res.Advice != "" {
			b.WriteString(fmt.Sprintf("  -> %s\n", res.Advice))
		}
	}
	if r.OK {
		b.WriteString("\nDiagnosis: no blocking issues detected.\n")
	} else {
		b.WriteString("\nDiagnosis: blocking issues found; see errors above.\n")
	}
	return b.String()
}
