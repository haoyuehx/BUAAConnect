package netownership

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
)

// ExtraRouteResourcePortMin and ExtraRouteResourcePortMax describe the port
// range of an extra-route IP resource. Extra routes only affect local
// forwarding: they must not be used to widen the server-side ACL.
const (
	ExtraRouteResourcePortMin = 1
	ExtraRouteResourcePortMax = 65535
)

// MergeExtraRoutes validates user-configured extra routes and merges them into
// the VPN IP resources. Every accepted prefix is appended both as an
// all-protocol IP resource (so TUN resource matching accepts it) and to the
// returned list of prefixes that should be installed on the TUN interface.
//
// Prefixes that contain one of serverIPs are skipped: routing the VPN
// server's own address through the tunnel would create an underlay loop.
// Invalid entries are reported as an error and no partial result is returned.
//
// ipSet is the static resource set (may be nil). It is immutable; this
// function does not mutate it, but uses it to log prefixes that are already
// covered by static resources. Use AppendExtraRoutesToIPSet to obtain a set
// that also contains the extra routes.
func MergeExtraRoutes(ipResources []client.IPResource, ipSet *netaddr.IPSet, extraRoutes []string, serverIPs []net.IP) ([]client.IPResource, []string, error) {
	if len(extraRoutes) == 0 {
		return ipResources, nil, nil
	}

	servers := normalizeServerIPs(serverIPs)
	merged := append([]client.IPResource(nil), ipResources...)
	prefixes := make([]string, 0, len(extraRoutes))
	seen := make(map[string]struct{}, len(extraRoutes))

	for _, raw := range extraRoutes {
		prefix, err := configs.NormalizeExtraRoute(raw)
		if err != nil {
			return ipResources, nil, err
		}
		if serverInPrefix(prefix, servers) {
			log.Printf("Warning: extra route %s contains the VPN server address; skipping it to avoid an underlay loop", prefix)
			continue
		}
		cidr := prefix.String()
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}

		ip := net.IP(prefix.Addr().AsSlice())
		merged = append(merged, client.IPResource{
			IPMin:    ip,
			IPMax:    append(net.IP(nil), ip...),
			PortMin:  ExtraRouteResourcePortMin,
			PortMax:  ExtraRouteResourcePortMax,
			Protocol: "all",
		})
		prefixes = append(prefixes, cidr)

		if ipSet != nil && prefixInIPSet(ipSet, prefix) {
			log.DebugPrintf("Extra route %s is already covered by a static resource; adding it idempotently", cidr)
		}
	}

	return merged, prefixes, nil
}

// AppendExtraRoutesToIPSet returns a new IPSet containing all ranges of the
// original set plus every valid extra route prefix. The input set is not
// modified. Server-address exclusion is the caller's responsibility; use
// MergeExtraRoutes to obtain a safe prefix list first.
func AppendExtraRoutesToIPSet(ipSet *netaddr.IPSet, prefixes []string) (*netaddr.IPSet, error) {
	builder := netaddr.IPSetBuilder{}
	if ipSet != nil {
		for _, ipRange := range ipSet.Ranges() {
			builder.AddRange(ipRange)
		}
	}
	for _, raw := range prefixes {
		prefix, err := configs.NormalizeExtraRoute(raw)
		if err != nil {
			return nil, err
		}
		addr, ok := netaddr.FromStdIP(prefix.Addr().AsSlice())
		if !ok {
			return nil, fmt.Errorf("extra route %s is not a valid IP", prefix)
		}
		builder.AddPrefix(netaddr.IPPrefixFrom(addr, uint8(prefix.Bits())))
	}
	return builder.IPSet()
}

func normalizeServerIPs(serverIPs []net.IP) []netip.Addr {
	servers := make([]netip.Addr, 0, len(serverIPs))
	for _, serverIP := range serverIPs {
		if serverIP == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(serverIP.To4())
		if !ok {
			continue
		}
		servers = append(servers, addr.Unmap())
	}
	return servers
}

func serverInPrefix(prefix netip.Prefix, servers []netip.Addr) bool {
	for _, server := range servers {
		if prefix.Contains(server) {
			return true
		}
	}
	return false
}

func prefixInIPSet(ipSet *netaddr.IPSet, prefix netip.Prefix) bool {
	addr, ok := netaddr.FromStdIP(prefix.Addr().AsSlice())
	if !ok {
		return false
	}
	return ipSet.ContainsPrefix(netaddr.IPPrefixFrom(addr, uint8(prefix.Bits())))
}
