package netownership

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/mythologyli/zju-connect/log"
)

// RouteManager adds routes through the TUN interface and remembers exactly
// which routes this process created. Rollback only removes those routes: a
// pre-existing route owned by the system (reported by `ip route add` as
// "File exists") is left untouched.
//
// RouteManager is safe for concurrent use and its cleanup methods are
// idempotent.
type RouteManager struct {
	interfaceName string
	runner        CommandRunner

	mu       sync.Mutex
	owned    []string
	ownedSet map[string]struct{}
}

// NewRouteManager creates a route manager for interfaceName. A nil runner uses
// the real system `ip` command.
func NewRouteManager(interfaceName string, runner CommandRunner) *RouteManager {
	return &RouteManager{
		interfaceName: interfaceName,
		runner:        normalizeRunner(runner),
		ownedSet:      make(map[string]struct{}),
	}
}

// InterfaceName returns the interface routes are installed on.
func (m *RouteManager) InterfaceName() string {
	if m == nil {
		return ""
	}
	return m.interfaceName
}

// AddRoute runs `ip route add <cidr> dev <interface>`. If the route already
// exists the caller (or another program) owns it: a warning is logged, the
// route is not recorded as ours, and no error is returned. Any other failure
// is returned to the caller.
func (m *RouteManager) AddRoute(cidr string) error {
	if m == nil {
		return errors.New("nil route manager")
	}
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return errors.New("empty route prefix")
	}
	if m.interfaceName == "" {
		return errors.New("route manager has no interface")
	}

	// Serialize command execution with rollback: otherwise a route could be
	// installed after Cleanup took its snapshot and leak into the system.
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ownedSet[cidr]; ok {
		return nil
	}

	ctx, cancel := commandContext()
	defer cancel()
	output, err := m.runner.Run(ctx, "ip", "route", "add", cidr, "dev", m.interfaceName)
	if err != nil {
		if isRouteAlreadyExists(output, err) {
			log.Printf("Warning: route %s already exists on %s; leaving the pre-existing route untouched", cidr, m.interfaceName)
			return nil
		}
		return fmt.Errorf("add route %s dev %s: %w%s", cidr, m.interfaceName, err, formatCommandOutput(output))
	}

	if m.ownedSet == nil {
		m.ownedSet = make(map[string]struct{})
	}
	m.ownedSet[cidr] = struct{}{}
	m.owned = append(m.owned, cidr)
	return nil
}

// Add is an alias for AddRoute.
func (m *RouteManager) Add(cidr string) error {
	return m.AddRoute(cidr)
}

// Routes returns a copy of the routes owned by this process, in insertion
// order.
func (m *RouteManager) Routes() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.owned...)
}

// Rollback removes every route owned by this process. Routes that were not
// added by us are never touched. Calling Rollback repeatedly is safe; a
// route is forgotten only after it was removed (or was already gone).
func (m *RouteManager) Rollback() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for i := len(m.owned) - 1; i >= 0; i-- {
		cidr := m.owned[i]
		ctx, cancel := commandContext()
		output, err := m.runner.Run(ctx, "ip", "route", "del", cidr, "dev", m.interfaceName)
		cancel()
		if err != nil {
			if isRouteAlreadyGone(output, err) {
				log.DebugPrintf("Route %s on %s was already removed", cidr, m.interfaceName)
			} else {
				errs = append(errs, fmt.Errorf("remove route %s dev %s: %w%s", cidr, m.interfaceName, err, formatCommandOutput(output)))
				continue
			}
		}
		delete(m.ownedSet, cidr)
		m.owned = append(m.owned[:i], m.owned[i+1:]...)
	}
	return errors.Join(errs...)
}

// Cleanup is an alias for Rollback kept for symmetry with DNSManager.
func (m *RouteManager) Cleanup() error {
	return m.Rollback()
}

func isRouteAlreadyExists(output []byte, err error) bool {
	return containsAnyCommandText(output, err, "file exists")
}

func isRouteAlreadyGone(output []byte, err error) bool {
	return containsAnyCommandText(output, err,
		"no such process",
		"cannot find device",
		"cannot find specified device",
		"no such file or directory",
	)
}

func containsAnyCommandText(output []byte, err error, needles ...string) bool {
	text := strings.ToLower(string(output))
	if err != nil {
		text += " " + strings.ToLower(err.Error())
	}
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func formatCommandOutput(output []byte) string {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return ""
	}
	return ": " + trimmed
}
