package service

import (
	"net"
	"testing"
)

func TestNewDnsServerHasNoLeadingNilServers(t *testing.T) {
	server := NewDnsServer(nil, []string{"10.0.0.1", "invalid", "10.0.0.2"})
	if len(server.localDNS) != 2 {
		t.Fatalf("localDNS = %#v, want two valid servers", server.localDNS)
	}
	for i, ip := range server.localDNS {
		if ip == nil {
			t.Fatalf("localDNS[%d] = nil", i)
		}
	}
	if !server.localDNS[0].Equal(net.IPv4(10, 0, 0, 1)) || !server.localDNS[1].Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("localDNS = %#v, want [10.0.0.1 10.0.0.2]", server.localDNS)
	}
}

func TestNewDnsServerEmptyInput(t *testing.T) {
	server := NewDnsServer(nil, nil)
	if server.localDNS == nil || len(server.localDNS) != 0 {
		t.Fatalf("localDNS = %#v, want empty non-nil slice", server.localDNS)
	}
}
