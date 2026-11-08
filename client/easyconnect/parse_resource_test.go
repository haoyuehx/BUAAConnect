package easyconnect

import (
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"inet.af/netaddr"
)

func TestParseResourcesPreservesMultipleRulesForDomain(t *testing.T) {
	resource := `<Resource><Rcs>
		<Rc type="1" proto="0" host="www.cnki.net" port="443~443" />
		<Rc type="1" proto="0" host="www.cnki.net" port="80~80" />
	</Rcs><Dns data="" dnsserver="10.0.0.1" /></Resource>`
	c := &Client{useDomainResource: true}
	if err := c.parseResources(resource); err != nil {
		t.Fatalf("parseResources() error = %v", err)
	}

	rules := c.domainResources["www.cnki.net"]
	if len(rules) != 2 {
		t.Fatalf("domain rules = %#v, want 2 rules", rules)
	}
	for _, port := range []int{80, 443} {
		if _, ok := client.MatchDomainResource(rules, "tcp", port); !ok {
			t.Fatalf("domain rules did not match tcp/%d: %#v", port, rules)
		}
	}
}

func TestParseResourcesAddsStaticDNSMappingsToIPResources(t *testing.T) {
	resource := `<Resource><Rcs></Rcs><Dns data="0:static.example.com:10.20.30.40;0:other.example.com:10.20.30.40" dnsserver="10.0.0.1" /></Resource>`
	c := &Client{useDomainResource: true}
	if err := c.parseResources(resource); err != nil {
		t.Fatalf("parseResources() error = %v", err)
	}

	if len(c.ipResources) != 1 {
		t.Fatalf("ipResources = %#v, want one deduplicated static DNS IP", c.ipResources)
	}
	got := c.ipResources[0]
	if !got.IPMin.Equal(net.IPv4(10, 20, 30, 40)) || !got.IPMax.Equal(got.IPMin) {
		t.Fatalf("static DNS resource IP = %s..%s, want 10.20.30.40", got.IPMin, got.IPMax)
	}
	if got.PortMin != 1 || got.PortMax != 65535 || got.Protocol != "all" {
		t.Fatalf("static DNS resource = %#v, want all ports/all protocols", got)
	}
	if c.ipSet == nil || !c.ipSet.Contains(netaddr.MustParseIP("10.20.30.40")) {
		t.Fatal("static DNS IP was not added to the IP set")
	}
	if _, ok := ipresource.New(c.ipResources).Match(net.IPv4(10, 20, 30, 40), "tcp", 443); !ok {
		t.Fatal("static DNS IP resource does not match tcp/443")
	}
}

func TestParseResourcesSkipsStaticDNSIPResourcesWithoutDomainMode(t *testing.T) {
	resource := `<Resource><Rcs></Rcs><Dns data="0:static.example.com:10.20.30.40" dnsserver="10.0.0.1" /></Resource>`
	c := &Client{useDomainResource: false}
	if err := c.parseResources(resource); err != nil {
		t.Fatalf("parseResources() error = %v", err)
	}
	if len(c.ipResources) != 0 {
		t.Fatalf("ipResources = %#v, want none when domain resources are disabled", c.ipResources)
	}
	if c.ipSet == nil || c.ipSet.Contains(netaddr.MustParseIP("10.20.30.40")) {
		t.Fatal("static DNS IP was added to the IP set without domain mode")
	}
}
