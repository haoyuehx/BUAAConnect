package underlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	tun "github.com/mythologyli/sing-tun"
	"github.com/mythologyli/zju-connect/internal/platformdialer"
	"github.com/mythologyli/zju-connect/log"
	"github.com/sagernet/sing/common/logger"
)

// Dialer creates connections on the interface that was used to reach the VPN
// server before the TUN interface was installed. This prevents VPN underlay
// connections from being captured by the TUN interface itself.
type Dialer struct {
	mu             sync.RWMutex
	interfaceName  string
	autoDetect     bool
	excludedIPs    []net.IP
	requireBound   bool
	capture        *pcapCapture
	localDNSServer string
}

// Options configures a Dialer.
type Options struct {
	// InterfaceName explicitly selects the interface used by underlay sockets.
	// It takes precedence over AutoDetect.
	InterfaceName string
	AutoDetect    bool
	// DebugPCAPFile records application-visible TCP traffic on underlay sockets.
	DebugPCAPFile string
	// LocalDNSServer overrides the system DNS for VPN server hostname resolution.
	// It must be an IP address with an optional port.
	LocalDNSServer string
}

// New creates an underlay dialer. With no options, interface auto-detection is
// enabled. The caller must close the returned dialer.
func New(options ...Options) (*Dialer, error) {
	option := Options{AutoDetect: true}
	if len(options) > 0 {
		option = options[0]
	}
	d := &Dialer{autoDetect: option.AutoDetect}
	localDNSServer, err := normalizeLocalDNSServer(option.LocalDNSServer)
	if err != nil {
		return nil, err
	}
	d.localDNSServer = localDNSServer
	if option.InterfaceName != "" {
		d.updateInterfaceName(option.InterfaceName)
		d.autoDetect = false
	}
	if option.DebugPCAPFile != "" {
		capture, err := newPCAPCapture(option.DebugPCAPFile)
		if err != nil {
			return nil, fmt.Errorf("initialize underlay PCAP capture: %w", err)
		}
		d.capture = capture
	}
	return d, nil
}

// Close flushes and closes the optional packet capture.
func (d *Dialer) Close() error {
	if d == nil {
		return nil
	}
	if d.capture != nil {
		return d.capture.Close()
	}
	return nil
}

// InterfaceName returns the currently selected underlay interface.
func (d *Dialer) InterfaceName() string {
	if d == nil {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.interfaceName
}

// ExcludeIP prevents an interface carrying ip from being selected as the
// underlay. VPN clients use this to exclude their own TUN interface.
func (d *Dialer) ExcludeIP(ip net.IP) {
	if d == nil || ip == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.excludedIPs = append(d.excludedIPs, append(net.IP(nil), ip...))
	d.requireBound = true
}

// PinInterface resolves and fixes the underlay interface before the TUN
// device is installed, returning its name. A manually configured interface is
// returned unchanged. With auto-detection the interface is resolved once
// (including a UDP probe towards address when the default-interface monitor
// cannot answer) so later control-plane traffic cannot be captured by the
// freshly created TUN device. A dialer without auto-detection stays unbound
// and returns an empty name.
func (d *Dialer) PinInterface(ctx context.Context, address string) (string, error) {
	if d == nil {
		return "", nil
	}
	d.mu.RLock()
	autoDetect := d.autoDetect
	interfaceName := d.interfaceName
	d.mu.RUnlock()
	if !autoDetect || interfaceName != "" {
		return interfaceName, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if address == "" {
		return "", errors.New("underlay interface probe requires a server address")
	}

	interfaceName = d.ensureInterface(address)
	if interfaceName == "" {
		interfaceName = d.refreshInterface()
	}
	if interfaceName == "" {
		return "", fmt.Errorf("no usable underlay interface for %s", address)
	}
	return interfaceName, nil
}

// DialContext connects through the selected underlay interface.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	interfaceName := d.ensureInterface(address)
	d.mu.RLock()
	autoDetect := d.autoDetect
	requireBound := d.requireBound
	d.mu.RUnlock()
	if autoDetect && requireBound && interfaceName == "" {
		interfaceName = d.refreshInterface()
		if interfaceName == "" {
			return nil, fmt.Errorf("no usable underlay interface")
		}
	}

	conn, err := dialOnInterface(ctx, network, address, interfaceName, d.localDNSServer)
	if err == nil {
		return d.wrapCapture(conn), nil
	}

	refreshedInterface := d.refreshInterface()
	if refreshedInterface == "" || refreshedInterface == interfaceName {
		return nil, err
	}

	conn, retryErr := dialOnInterface(ctx, network, address, refreshedInterface, d.localDNSServer)
	if retryErr != nil {
		return nil, fmt.Errorf("dial underlay via %q failed after %q failed: %w", refreshedInterface, interfaceName, retryErr)
	}
	return d.wrapCapture(conn), nil
}

func (d *Dialer) ensureInterface(address string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.autoDetect || d.interfaceName != "" {
		return d.interfaceName
	}
	if interfaceName := detectInterface(address); usableInterface(interfaceName, d.excludedIPs) {
		d.updateInterfaceName(interfaceName)
	}
	return d.interfaceName
}

func (d *Dialer) updateInterfaceName(interfaceName string) {
	if interfaceName == "" || interfaceName == d.interfaceName {
		return
	}
	d.interfaceName = interfaceName
	log.Printf("Underlay interface: %s", interfaceName)
}

func (d *Dialer) wrapCapture(conn net.Conn) net.Conn {
	if d.capture == nil {
		return conn
	}
	return d.capture.Wrap(conn)
}

func dialContextOnInterface(ctx context.Context, network, address, interfaceName, localDNSServer string) (net.Conn, error) {
	dialer := &platformdialer.Dialer{InterfaceName: interfaceName}
	if interfaceName != "" || localDNSServer != "" {
		dialer.Resolver = newUnderlayResolver(interfaceName, localDNSServer)
	}
	return dialer.DialContext(ctx, network, address)
}

func newUnderlayResolver(interfaceName, localDNSServer string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, systemDNSServer string) (net.Conn, error) {
			target := systemDNSServer
			if localDNSServer != "" {
				target = localDNSServer
			}
			boundInterface := interfaceName
			if isLoopbackAddress(target) {
				boundInterface = ""
			}
			dialer := &platformdialer.Dialer{InterfaceName: boundInterface}
			return dialer.DialContext(ctx, network, target)
		},
	}
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeLocalDNSServer(address string) (string, error) {
	if address == "" {
		return "", nil
	}
	if ip := net.ParseIP(address); ip != nil {
		return net.JoinHostPort(address, "53"), nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return "", fmt.Errorf("local DNS server must be an IP address with an optional port: %q", address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid local DNS server port in %q", address)
	}
	return net.JoinHostPort(host, port), nil
}

var dialOnInterface = dialContextOnInterface

// DialTimeout connects through the underlay with the provided timeout.
func (d *Dialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func detectInterface(targetAddress string) string {
	if interfaceName := findDefaultInterface(); usableInterface(interfaceName, nil) {
		return interfaceName
	}

	// This fallback is primarily for platforms without a default-interface
	// monitor. The first DialContext runs before the TUN interface is installed.
	host, port, err := net.SplitHostPort(targetAddress)
	if err != nil {
		host = targetAddress
		port = "443"
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return ""
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && ip.Equal(localIP) {
				if usableInterface(iface.Name, nil) {
					return iface.Name
				}
				return ""
			}
		}
	}
	return ""
}

func (d *Dialer) refreshInterface() string {
	d.mu.RLock()
	autoDetect := d.autoDetect
	d.mu.RUnlock()
	if !autoDetect {
		return ""
	}

	interfaceName := findDefaultInterface()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !usableInterface(interfaceName, d.excludedIPs) {
		return ""
	}
	d.updateInterfaceName(interfaceName)
	return interfaceName
}

var findDefaultInterface = detectDefaultInterface

func detectDefaultInterface() string {
	networkMonitor, err := tun.NewNetworkUpdateMonitor(logger.NOP())
	if err != nil {
		return ""
	}
	if err := networkMonitor.Start(); err != nil {
		_ = networkMonitor.Close()
		return ""
	}
	defer networkMonitor.Close()

	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, logger.NOP(), tun.DefaultInterfaceMonitorOptions{OverrideAndroidVPN: true})
	if err != nil {
		return ""
	}
	if err := interfaceMonitor.Start(); err != nil {
		_ = interfaceMonitor.Close()
		return ""
	}
	defer interfaceMonitor.Close()

	return interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified())
}

// virtualUnderlayInterfacePrefixes lists interface names that are normally
// TUN/point-to-point or proxy TUN devices. Binding the underlay (the transport
// used to reach the VPN server) to one of them would route VPN traffic back
// into the VPN tunnel. Explicitly configured bind_interface values bypass this
// filter; it only applies to auto-detection.
var virtualUnderlayInterfacePrefixes = []string{
	"tun",
	"utun",
	"meta",
	"mihomo",
	"clash",
	"buaa",
	"zju-connect",
}

func isVirtualUnderlayInterfaceName(interfaceName string) bool {
	name := strings.ToLower(strings.TrimSpace(interfaceName))
	if name == "" {
		return false
	}
	for _, prefix := range virtualUnderlayInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// interfaceFlagsUsable rejects interfaces that cannot carry the underlay:
// down/loopback interfaces and point-to-point links such as tun devices.
func interfaceFlagsUsable(flags net.Flags) bool {
	return flags&net.FlagUp != 0 &&
		flags&net.FlagLoopback == 0 &&
		flags&net.FlagPointToPoint == 0
}

func usableInterface(interfaceName string, excludedIPs []net.IP) bool {
	if interfaceName == "" {
		return false
	}
	if isVirtualUnderlayInterfaceName(interfaceName) {
		return false
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil || !interfaceFlagsUsable(iface.Flags) {
		return false
	}
	if len(excludedIPs) == 0 {
		return true
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		var interfaceIP net.IP
		switch value := address.(type) {
		case *net.IPNet:
			interfaceIP = value.IP
		case *net.IPAddr:
			interfaceIP = value.IP
		}
		for _, excludedIP := range excludedIPs {
			if interfaceIP != nil && interfaceIP.Equal(excludedIP) {
				return false
			}
		}
	}
	return true
}
