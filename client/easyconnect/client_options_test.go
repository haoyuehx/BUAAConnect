package easyconnect

import (
	"crypto/tls"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/underlay"
)

func TestNewClientMapsOptions(t *testing.T) {
	dialer := newTestUnderlay(t, underlay.Options{AutoDetect: false})
	certificate := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	var keyLogWriter strings.Builder
	challengeHandler := authchallenge.HandlerFuncs{}

	c := NewClient(Options{
		Server: "vpn.example.com:443",
		Auth: AuthOptions{
			Username:      "user",
			Password:      "password",
			TOTPSecret:    "totp-secret",
			Certificate:   certificate,
			GraphCodeFile: "graph-code.txt",
		},
		SessionID:     "session-id",
		TestMultiLine: true,
		Resources: ResourceOptions{
			Fetch:          true,
			IncludeDomains: true,
		},
		UnderlayDialer:   dialer,
		TLSKeyLogWriter:  &keyLogWriter,
		ChallengeHandler: challengeHandler,
	})
	t.Cleanup(c.Close)

	if c.server != "vpn.example.com:443" || c.username != "user" || c.password != "password" {
		t.Fatalf("basic options were not mapped: %+v", c)
	}
	if c.totpSecret != "totp-secret" || c.graphCodeFile != "graph-code.txt" {
		t.Fatal("authentication options were not mapped")
	}
	if !reflect.DeepEqual(c.tlsCert.Certificate, certificate.Certificate) {
		t.Fatal("certificate option was not mapped")
	}
	if c.twfID != "session-id" || !c.testMultiLine || !c.parseResource || !c.useDomainResource {
		t.Fatal("session or resource options were not mapped")
	}
	if c.underlayDialer != dialer || c.tlsKeyLogWriter != &keyLogWriter {
		t.Fatal("transport dependencies were not mapped")
	}
	if reflect.TypeOf(c.challengeHandler) != reflect.TypeOf(challengeHandler) {
		t.Fatalf("challenge handler type = %T, want %T", c.challengeHandler, challengeHandler)
	}
}

func TestNewClientMapsReconnectOptions(t *testing.T) {
	client := NewClient(Options{
		Server:         "vpn.example.com:443",
		MaxReconnect:   3,
		ReconnectDelay: 250 * time.Millisecond,
	})
	t.Cleanup(client.Close)

	if client.maxReconnect != 3 {
		t.Fatalf("maxReconnect = %d, want 3", client.maxReconnect)
	}
	if client.reconnectDelay != 250*time.Millisecond {
		t.Fatalf("reconnectDelay = %s, want 250ms", client.reconnectDelay)
	}
}

func TestNewClientReconnectDefaults(t *testing.T) {
	for _, tt := range []struct {
		name      string
		max       int
		delay     time.Duration
		wantMax   int
		wantDelay time.Duration
	}{
		{name: "zero values", wantMax: defaultL3ReconnectLimit, wantDelay: defaultL3ReconnectDelay},
		{
			name:      "negative values",
			max:       -2,
			delay:     -time.Second,
			wantMax:   defaultL3ReconnectLimit,
			wantDelay: defaultL3ReconnectDelay,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(Options{MaxReconnect: tt.max, ReconnectDelay: tt.delay})
			t.Cleanup(client.Close)
			if client.maxReconnect != tt.wantMax || client.reconnectDelay != tt.wantDelay {
				t.Fatalf("reconnect policy = (%d, %s), want (%d, %s)",
					client.maxReconnect, client.reconnectDelay, tt.wantMax, tt.wantDelay)
			}
		})
	}
}

func TestServerHostReturnsSelectedLine(t *testing.T) {
	client := NewClient(Options{Server: "line-a.example.com:443"})
	t.Cleanup(client.Close)
	if got := client.ServerHost(); got != "line-a.example.com:443" {
		t.Fatalf("ServerHost() = %q, want %q", got, "line-a.example.com:443")
	}

	// Multi-line probing replaces the initial server with the best line.
	client.server = "line-b.example.com:443"
	if got := client.ServerHost(); got != "line-b.example.com:443" {
		t.Fatalf("ServerHost() after line selection = %q, want %q", got, "line-b.example.com:443")
	}

	var nilClient *Client
	if got := nilClient.ServerHost(); got != "" {
		t.Fatalf("nil ServerHost() = %q, want empty", got)
	}
}

func TestResourceOptionsTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name           string
		fetch          bool
		includeDomains bool
	}{
		{name: "neither"},
		{name: "fetch only", fetch: true},
		{name: "domains only", includeDomains: true},
		{name: "both", fetch: true, includeDomains: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(Options{Resources: ResourceOptions{
				Fetch:          tt.fetch,
				IncludeDomains: tt.includeDomains,
			}})
			t.Cleanup(c.Close)
			if c.parseResource != tt.fetch || c.useDomainResource != tt.includeDomains {
				t.Fatalf("resource state = (%t, %t), want (%t, %t)",
					c.parseResource, c.useDomainResource, tt.fetch, tt.includeDomains)
			}
		})
	}
}
