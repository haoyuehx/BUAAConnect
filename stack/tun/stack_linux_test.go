//go:build linux

package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/netownership"
	"inet.af/netaddr"
)

type optionTestClient struct{}

func (optionTestClient) IP() (net.IP, error)                       { return net.IPv4(10, 0, 0, 2), nil }
func (optionTestClient) IPSet() (*netaddr.IPSet, error)            { return nil, errors.New("unused") }
func (optionTestClient) IPResources() ([]client.IPResource, error) { return nil, nil }
func (optionTestClient) DomainResources() (client.DomainResources, error) {
	return client.DomainResources{}, nil
}
func (optionTestClient) DNSResource() (map[string][]net.IP, error) { return nil, errors.New("unused") }
func (optionTestClient) DNSServer() (string, error)                { return "", errors.New("unused") }
func (optionTestClient) DNSServers() ([]string, error)             { return nil, errors.New("unused") }
func (optionTestClient) CanUseTCPTunnel() bool                     { return false }
func (optionTestClient) DialTCP(context.Context, *net.TCPAddr) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (optionTestClient) NewL3Conn() (io.ReadWriteCloser, error) {
	return nil, errors.New("unused")
}

func TestNewStackWithOptionsRejectsNilClient(t *testing.T) {
	if _, err := NewStackWithOptions(nil, Options{}); err == nil {
		t.Fatal("NewStackWithOptions(nil) error = nil, want error")
	}
}

func TestNewStackWithOptionsRejectsInvalidExtraRoute(t *testing.T) {
	_, err := NewStackWithOptions(optionTestClient{}, Options{ExtraRoutes: []string{"not-a-cidr"}})
	if err == nil || !strings.Contains(err.Error(), "merge extra routes") {
		t.Fatalf("error = %v, want extra-route validation error", err)
	}
}

func TestStackCleanupIsIdempotentWithoutResources(t *testing.T) {
	s := &Stack{}
	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if err := s.Cleanup(); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}
}

func TestStackCleanupRevertsDNSBeforeRollingBackRoutes(t *testing.T) {
	var mu sync.Mutex
	var commands []string
	runner := netownership.CommandRunnerFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		mu.Unlock()
		return nil, nil
	})

	s := &Stack{
		routeManager: netownership.NewRouteManager("buaa-test0", runner),
		dnsManager:   netownership.NewDNSManager("buaa-test0", netownership.DNSModeResolvectl, runner),
	}
	if err := s.routeManager.AddRoute("10.0.0.0/8"); err != nil {
		t.Fatalf("AddRoute(10.0.0.0/8) error = %v", err)
	}
	if err := s.routeManager.AddRoute("172.16.0.0/12"); err != nil {
		t.Fatalf("AddRoute(172.16.0.0/12) error = %v", err)
	}
	if err := s.dnsManager.Configure(net.IPv4(10, 0, 0, 2), []string{"~buaa.edu.cn"}); err != nil {
		t.Fatalf("DNS Configure() error = %v", err)
	}

	mu.Lock()
	commands = nil
	mu.Unlock()

	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	mu.Lock()
	got := append([]string(nil), commands...)
	mu.Unlock()
	want := []string{
		"resolvectl revert buaa-test0",
		"ip route del 172.16.0.0/12 dev buaa-test0",
		"ip route del 10.0.0.0/8 dev buaa-test0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanup commands = %q, want DNS revert followed by reverse-order route deletes %q", got, want)
	}
	if routes := s.AddedRoutes(); len(routes) != 0 {
		t.Fatalf("routes after Cleanup = %q, want none", routes)
	}

	// A second Cleanup is a no-op and must not re-run any command.
	mu.Lock()
	commands = nil
	mu.Unlock()
	if err := s.Cleanup(); err != nil {
		t.Fatalf("second Cleanup() error = %v", err)
	}
	mu.Lock()
	secondRun := append([]string(nil), commands...)
	mu.Unlock()
	if len(secondRun) != 0 {
		t.Fatalf("second Cleanup() ran commands = %q, want none", secondRun)
	}
}

func TestStackCleanupAggregatesDNSAndRouteErrors(t *testing.T) {
	routeFailure := errors.New("route delete denied")
	dnsFailure := errors.New("resolvectl revert denied")
	runner := netownership.CommandRunnerFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		command := strings.Join(append([]string{name}, args...), " ")
		switch command {
		case "resolvectl revert buaa-test1":
			return []byte("Failed to revert: access denied"), dnsFailure
		case "ip route del 10.0.0.0/8 dev buaa-test1":
			return []byte("RTNETLINK answers: Operation not permitted"), routeFailure
		}
		return nil, nil
	})

	s := &Stack{
		routeManager: netownership.NewRouteManager("buaa-test1", runner),
		dnsManager:   netownership.NewDNSManager("buaa-test1", netownership.DNSModeResolvectl, runner),
	}
	if err := s.routeManager.AddRoute("10.0.0.0/8"); err != nil {
		t.Fatalf("AddRoute(10.0.0.0/8) error = %v", err)
	}
	if err := s.routeManager.AddRoute("192.168.0.0/16"); err != nil {
		t.Fatalf("AddRoute(192.168.0.0/16) error = %v", err)
	}
	if err := s.dnsManager.Configure(net.IPv4(10, 0, 0, 2), []string{"~buaa.edu.cn"}); err != nil {
		t.Fatalf("DNS Configure() error = %v", err)
	}

	err := s.Cleanup()
	if err == nil {
		t.Fatal("Cleanup() error = nil, want joined DNS and route errors")
	}
	if !strings.Contains(err.Error(), "resolvectl revert") {
		t.Fatalf("Cleanup() error = %v, want DNS revert failure", err)
	}
	if !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Fatalf("Cleanup() error = %v, want route delete failure", err)
	}

	// The successfully removed route stays gone; only the failing one remains
	// tracked for a later retry.
	if routes := s.AddedRoutes(); !reflect.DeepEqual(routes, []string{"10.0.0.0/8"}) {
		t.Fatalf("routes after failed Cleanup = %q, want [10.0.0.0/8]", routes)
	}
}

func TestStackErrReportsFirstFatalError(t *testing.T) {
	s := &Stack{}
	first := errors.New("first failure")
	second := errors.New("second failure")
	s.reportError(first)
	s.reportError(second)

	select {
	case err := <-s.Err():
		if !errors.Is(err, first) {
			t.Fatalf("Err() = %v, want first error", err)
		}
	default:
		t.Fatal("Err() did not receive the reported error")
	}
}

func TestStackAccessorsAreNilSafe(t *testing.T) {
	s := &Stack{}
	if s.InterfaceName() != "" {
		t.Fatalf("InterfaceName() = %q, want empty", s.InterfaceName())
	}
	if s.ClientIP() != nil {
		t.Fatalf("ClientIP() = %v, want nil", s.ClientIP())
	}
	if got := s.AddedRoutes(); got != nil {
		t.Fatalf("AddedRoutes() = %#v, want nil", got)
	}
}
