package netownership

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/mythologyli/zju-connect/log"
)

const (
	// DNSModeAuto uses resolvectl when it works and degrades to the system
	// resolver (without failing the connection) when it does not.
	DNSModeAuto = "auto"
	// DNSModeResolvectl requires resolvectl; errors are returned to the caller.
	DNSModeResolvectl = "resolvectl"
	// DNSModeOff leaves system DNS configuration untouched.
	DNSModeOff = "off"
)

// DefaultDNSDomains contains the BUAA domain suffixes that should be resolved
// through the VPN TUN interface by default. A leading '~' marks a resolvectl
// routing-only domain; the global "~." default route is intentionally not
// included unless the user configures it explicitly.
var DefaultDNSDomains = []string{"~buaa.edu.cn"}

// NormalizeDNSMode validates the configured system_dns mode.
func NormalizeDNSMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", DNSModeOff:
		return DNSModeOff, nil
	case DNSModeAuto:
		return DNSModeAuto, nil
	case DNSModeResolvectl:
		return DNSModeResolvectl, nil
	default:
		return "", fmt.Errorf("invalid system_dns mode %q (expected %q, %q or %q)", mode, DNSModeAuto, DNSModeResolvectl, DNSModeOff)
	}
}

// NormalizeDNSDomain makes a server-provided suffix usable as a resolvectl
// routing domain. Wildcards and leading dots are removed and a routing-only
// prefix '~' is added. The explicit global domain "~." is preserved.
func NormalizeDNSDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if domain == "~." || domain == "." {
		return "~."
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return ""
	}
	if !strings.HasPrefix(domain, "~") {
		domain = "~" + domain
	}
	return domain
}

// MergeDNSDomains flattens and normalizes several domain lists, keeping the
// first occurrence of each domain. The global "~." is only kept when it was
// passed in explicitly.
func MergeDNSDomains(groups ...[]string) []string {
	seen := make(map[string]struct{})
	merged := make([]string, 0)
	for _, group := range groups {
		for _, domain := range group {
			normalized := NormalizeDNSDomain(domain)
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			merged = append(merged, normalized)
		}
	}
	return merged
}

// DNSManager configures split DNS on the TUN interface through resolvectl.
// It is safe for concurrent use and Revert is idempotent.
type DNSManager struct {
	interfaceName string
	mode          string
	runner        CommandRunner

	mu         sync.Mutex
	validMode  bool
	configured bool
}

// NewDNSManager creates a manager for interfaceName. A nil runner uses the
// real resolvectl binary. An unknown mode is reported by Configure instead of
// being silently ignored.
func NewDNSManager(interfaceName, mode string, runner CommandRunner) *DNSManager {
	normalized, err := NormalizeDNSMode(mode)
	return &DNSManager{
		interfaceName: interfaceName,
		mode:          normalized,
		runner:        normalizeRunner(runner),
		validMode:     err == nil,
	}
}

// Mode returns the normalized system_dns mode ("off" for an empty value).
func (m *DNSManager) Mode() string {
	if m == nil {
		return DNSModeOff
	}
	return m.mode
}

// Configured reports whether Configure successfully applied resolvectl state.
func (m *DNSManager) Configured() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.configured
}

// Configure sets the VPN DNS server and split-DNS domains on the interface.
//
// In "auto" mode every resolvectl failure is logged as a degradation warning
// and nil is returned, so a missing resolvectl never breaks the connection.
// In "resolvectl" mode failures are returned. In "off" mode nothing is run.
func (m *DNSManager) Configure(vip net.IP, domains []string) error {
	if m == nil || m.mode == DNSModeOff {
		return nil
	}
	if !m.validMode {
		return fmt.Errorf("invalid system_dns mode %q", m.mode)
	}
	if m.interfaceName == "" {
		return errors.New("system DNS manager has no interface")
	}
	if vip == nil {
		return errors.New("system DNS manager requires the client VIP")
	}
	if len(domains) == 0 {
		domains = DefaultDNSDomains
	}

	// Keep Configure/Revert serialized so a shutdown race cannot leave
	// resolvectl configured after Cleanup returned.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.configured {
		return nil
	}

	if err := m.run("dns", m.interfaceName, vip.String()); err != nil {
		return m.degrade("resolvectl dns", err)
	}
	args := append([]string{"domain", m.interfaceName}, domains...)
	if err := m.run(args...); err != nil {
		// Do not leave a half-configured interface behind.
		_, _ = m.revertLocked()
		return m.degrade("resolvectl domain", err)
	}

	m.configured = true
	log.Printf("System DNS: %s via resolvectl on %s (%s)", vip.String(), m.interfaceName, strings.Join(domains, ", "))
	return nil
}

// Revert removes the resolvectl configuration for the interface. It is safe
// to call when Configure was never called or to call multiple times.
func (m *DNSManager) Revert() error {
	if m == nil || m.mode == DNSModeOff {
		return nil
	}
	if !m.validMode {
		return fmt.Errorf("invalid system_dns mode %q", m.mode)
	}
	if m.interfaceName == "" {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured {
		return nil
	}
	output, err := m.revertLocked()
	m.configured = false
	if err != nil {
		if m.mode == DNSModeAuto {
			log.Printf("Warning: resolvectl revert %s failed: %v%s (continuing shutdown)", m.interfaceName, err, formatCommandOutput(output))
			return nil
		}
		return fmt.Errorf("resolvectl revert %s: %w%s", m.interfaceName, err, formatCommandOutput(output))
	}
	log.Printf("System DNS: reverted resolvectl configuration on %s", m.interfaceName)
	return nil
}

func (m *DNSManager) revertLocked() ([]byte, error) {
	ctx, cancel := commandContext()
	defer cancel()
	return m.runner.Run(ctx, "resolvectl", "revert", m.interfaceName)
}

func (m *DNSManager) run(args ...string) error {
	ctx, cancel := commandContext()
	defer cancel()
	output, err := m.runner.Run(ctx, "resolvectl", args...)
	if err != nil {
		return fmt.Errorf("resolvectl %s: %w%s", strings.Join(args, " "), err, formatCommandOutput(output))
	}
	return nil
}

func (m *DNSManager) degrade(operation string, err error) error {
	if m.mode == DNSModeResolvectl {
		return fmt.Errorf("system DNS (%s) failed: %w", operation, err)
	}
	log.Printf("Warning: %s failed: %v; continuing with system resolver (degraded DNS split)", operation, err)
	return nil
}
