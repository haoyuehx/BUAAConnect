//go:build linux

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"

	tun "github.com/mythologyli/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/internal/netownership"
	"github.com/mythologyli/zju-connect/log"
)

type Endpoint struct {
	client client.Client

	ifce      tun.Tun
	ifceName  string
	readLock  sync.Mutex
	writeLock sync.Mutex
	configMu  sync.RWMutex
	ip        net.IP

	tcpDialer *net.Dialer
	udpDialer *net.Dialer
}

func (ep *Endpoint) Write(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	ep.writeLock.Lock()
	defer ep.writeLock.Unlock()
	_, err := ep.ifce.Write(buf)
	return err
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	ep.readLock.Lock()
	defer ep.readLock.Unlock()
	return ep.ifce.Read(buf)
}

// AddRoute adds a route through the TUN interface. Routes successfully added
// here are tracked for Cleanup, while pre-existing routes are left untouched.
func (s *Stack) AddRoute(target string) error {
	if s.routeManager == nil {
		return errors.New("route manager is not initialized")
	}
	return s.routeManager.AddRoute(target)
}

// InterfaceName returns the name of the TUN interface.
func (s *Stack) InterfaceName() string {
	if s == nil || s.endpoint == nil {
		return ""
	}
	return s.endpoint.ifceName
}

// ClientIP returns the virtual IP assigned to the TUN interface.
func (s *Stack) ClientIP() net.IP {
	if s == nil || s.endpoint == nil {
		return nil
	}
	s.endpoint.configMu.RLock()
	defer s.endpoint.configMu.RUnlock()
	return append(net.IP(nil), s.endpoint.ip...)
}

// AddedRoutes returns the routes this process added through the TUN interface.
func (s *Stack) AddedRoutes() []string {
	if s == nil || s.routeManager == nil {
		return nil
	}
	return s.routeManager.Routes()
}

// Cleanup reverts the system DNS configuration, removes only the routes this
// process added, and closes the TUN device. It is idempotent and safe for
// concurrent callers (for example the terminal hook and main).
func (s *Stack) Cleanup() error {
	if s == nil {
		return nil
	}
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	if s.cleanupDone {
		return s.cleanupErr
	}

	var errs []error
	if s.dnsManager != nil {
		if err := s.dnsManager.Revert(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.routeManager != nil {
		if err := s.routeManager.Rollback(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.endpoint != nil && s.endpoint.ifce != nil {
		if err := s.endpoint.ifce.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	s.cleanupErr = errors.Join(errs...)
	s.cleanupDone = true
	return s.cleanupErr
}

// NewStack keeps the historical constructor signature.
func NewStack(vpnClient client.Client, dnsHijack, fakeIP bool, ipResources []client.IPResource) (*Stack, error) {
	return NewStackWithOptions(vpnClient, Options{
		DNSHijack:   dnsHijack,
		FakeIP:      fakeIP,
		IPResources: ipResources,
	})
}

// NewStackWithOptions creates the Linux TUN stack, applies extra routes and
// optional resolvectl split DNS, and registers cleanup with the terminal hook
// handler. Callers that want to integrate the exit error with their own
// shutdown path should select on Err().
func NewStackWithOptions(vpnClient client.Client, opts Options) (*Stack, error) {
	if vpnClient == nil {
		return nil, errors.New("vpn client is required")
	}
	var err error
	s := &Stack{}
	s.fakeIP = opts.FakeIP
	s.endpoint = &Endpoint{
		client: vpnClient,
	}

	s.endpoint.ip, err = vpnClient.IP()
	if err != nil {
		return nil, err
	}

	resources := opts.IPResources
	extraPrefixes := []string(nil)
	if len(opts.ExtraRoutes) > 0 {
		resources, extraPrefixes, err = netownership.MergeExtraRoutes(resources, nil, opts.ExtraRoutes, opts.ServerIPs)
		if err != nil {
			return nil, fmt.Errorf("merge extra routes: %w", err)
		}
	}
	s.ipResources = resources

	ipPrefix, err := netip.ParsePrefix(s.endpoint.ip.String() + "/32")
	if err != nil {
		return nil, fmt.Errorf("parse client IP %s: %w", s.endpoint.ip, err)
	}
	tunName := opts.TunName
	if tunName == "" {
		tunName = tun.CalculateInterfaceName(DefaultTunNamePrefix)
	}

	tunOptions := tun.Options{
		Name: tunName,
		MTU:  MTU,
		Inet4Address: []netip.Prefix{
			ipPrefix,
		},
	}
	if opts.DNSHijack {
		tunOptions.AutoRoute = true
		tunOptions.TableIndex = 1897
	}
	ifce, err := tun.New(tunOptions)
	if err != nil {
		return nil, err
	}
	s.endpoint.ifce = ifce
	s.endpoint.ifceName = tunName
	s.routeManager = netownership.NewRouteManager(tunName, opts.RouteRunner)
	s.dnsManager = netownership.NewDNSManager(tunName, opts.SystemDNS, opts.DNSRunner)
	hook_func.RegisterTerminalFunc("Cleanup TUN resources", func(ctx context.Context) error {
		return s.Cleanup()
	})
	log.Printf("Interface Name: %s\n", tunName)

	// Extra routes are explicitly requested; failures are reported but do not
	// abort the connection. Only routes we actually add are tracked.
	for _, prefix := range extraPrefixes {
		log.Printf("Add extra route to %s", prefix)
		if err := s.routeManager.AddRoute(prefix); err != nil {
			log.Printf("Warning: failed to add extra route %s: %v", prefix, err)
		}
	}

	if dnsManager := s.dnsManager; dnsManager.Mode() != netownership.DNSModeOff {
		// Server-advertised suffixes are added as routing-only domains. The
		// global "~." is only honoured when the user configured it explicitly.
		var serverDomains []string
		if domainResources, domainErr := vpnClient.DomainResources(); domainErr == nil {
			for domain := range domainResources {
				if netownership.NormalizeDNSDomain(domain) == "~." {
					continue
				}
				serverDomains = append(serverDomains, domain)
			}
		}
		domains := netownership.MergeDNSDomains(netownership.DefaultDNSDomains, serverDomains, opts.DNSDomains)
		if err := dnsManager.Configure(s.endpoint.ip, domains); err != nil {
			_ = s.Cleanup()
			return nil, err
		}
	}

	// We need this dialer to bind to device otherwise packets will not be sent via TUN
	s.endpoint.tcpDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.BindToDevice(int(fd), s.endpoint.ifceName); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifceName)
				}
			})
		},
	}

	s.endpoint.udpDialer = &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.BindToDevice(int(fd), s.endpoint.ifceName); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifceName)
				}
			})
		},
	}
	client.RegisterIPUpdateHandler(vpnClient, s.updateIP)

	return s, nil
}

func (s *Stack) updateIP(ip net.IP) error {
	newIP := ip.To4()
	if newIP == nil {
		return fmt.Errorf("virtual IP update is not IPv4")
	}
	s.endpoint.configMu.Lock()
	defer s.endpoint.configMu.Unlock()
	oldIP := append(net.IP(nil), s.endpoint.ip...)
	if oldIP.Equal(newIP) {
		return nil
	}
	add := exec.Command("ip", "address", "replace", newIP.String()+"/32", "dev", s.endpoint.ifceName)
	if output, err := add.CombinedOutput(); err != nil {
		return fmt.Errorf("add virtual IP: %w: %s", err, output)
	}
	del := exec.Command("ip", "address", "del", oldIP.String()+"/32", "dev", s.endpoint.ifceName)
	if output, err := del.CombinedOutput(); err != nil {
		_ = exec.Command("ip", "address", "del", newIP.String()+"/32", "dev", s.endpoint.ifceName).Run()
		return fmt.Errorf("remove old virtual IP: %w: %s", err, output)
	}
	s.endpoint.ip = append(net.IP(nil), newIP...)
	s.endpoint.tcpDialer.LocalAddr = &net.TCPAddr{IP: append(net.IP(nil), newIP...)}
	s.endpoint.udpDialer.LocalAddr = &net.UDPAddr{IP: append(net.IP(nil), newIP...)}
	return nil
}
