package atrust

import (
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/underlay"
)

func TestNewClientMapsOptions(t *testing.T) {
	dialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	var keyLogWriter strings.Builder

	c := NewClient(ClientOptions{
		Session: SessionOptions{
			Username: "user",
			SID:      "sid",
			DeviceID: "device-id",
			SignKey:  "sign-key",
		},
		UnderlayDialer:  dialer,
		TLSKeyLogWriter: &keyLogWriter,
	})
	t.Cleanup(c.Close)

	if c.Username != "user" || c.SID != "sid" || c.DeviceID != "device-id" || c.SignKey != "sign-key" {
		t.Fatalf("session options were not mapped: %+v", c)
	}
	if c.underlayDialer != dialer || c.tlsKeyLogWriter != &keyLogWriter {
		t.Fatal("transport dependencies were not mapped")
	}
}

func TestNewClientMapsReconnectOptions(t *testing.T) {
	c := NewClient(ClientOptions{
		MaxReconnect:   2,
		ReconnectDelay: 750 * time.Millisecond,
	})
	t.Cleanup(c.Close)

	if c.maxReconnect != 2 {
		t.Fatalf("maxReconnect = %d, want 2", c.maxReconnect)
	}
	if c.reconnectDelay != 750*time.Millisecond {
		t.Fatalf("reconnectDelay = %s, want 750ms", c.reconnectDelay)
	}
}

func TestSetupOptionsOverrideReconnectPolicy(t *testing.T) {
	c := NewClient(ClientOptions{MaxReconnect: 2, ReconnectDelay: time.Second})
	t.Cleanup(c.Close)

	// Zero values keep the ClientOptions policy.
	c.applyReconnectOptions(SetupOptions{})
	if c.maxReconnect != 2 || c.reconnectDelay != time.Second {
		t.Fatalf("policy after empty SetupOptions = (%d, %s), want (2, 1s)", c.maxReconnect, c.reconnectDelay)
	}

	c.applyReconnectOptions(SetupOptions{MaxReconnect: 7, ReconnectDelay: 100 * time.Millisecond})
	if c.maxReconnect != 7 {
		t.Fatalf("maxReconnect = %d, want 7", c.maxReconnect)
	}
	if c.reconnectDelay != 100*time.Millisecond {
		t.Fatalf("reconnectDelay = %s, want 100ms", c.reconnectDelay)
	}

	// Negative values are ignored as well.
	c.applyReconnectOptions(SetupOptions{MaxReconnect: -1, ReconnectDelay: -time.Second})
	if c.maxReconnect != 7 || c.reconnectDelay != 100*time.Millisecond {
		t.Fatalf("policy after negative SetupOptions = (%d, %s), want (7, 100ms)", c.maxReconnect, c.reconnectDelay)
	}
}

func TestServerHostReturnsConfiguredServer(t *testing.T) {
	c := NewClient(ClientOptions{})
	t.Cleanup(c.Close)
	c.serverAddress = "vpn.example.com:8443"
	if got := c.ServerHost(); got != "vpn.example.com:8443" {
		t.Fatalf("ServerHost() = %q, want %q", got, "vpn.example.com:8443")
	}

	var nilClient *Client
	if got := nilClient.ServerHost(); got != "" {
		t.Fatalf("nil ServerHost() = %q, want empty", got)
	}
}

func TestCanResumeTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name         string
		sid          string
		deviceID     string
		resourceData []byte
		want         bool
	}{
		{name: "all present", sid: "sid", deviceID: "device", resourceData: []byte("resource"), want: true},
		{name: "empty but present resource", sid: "sid", deviceID: "device", resourceData: []byte{}, want: true},
		{name: "missing SID", deviceID: "device", resourceData: []byte("resource")},
		{name: "missing device", sid: "sid", resourceData: []byte("resource")},
		{name: "nil resource", sid: "sid", deviceID: "device"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(ClientOptions{Session: SessionOptions{SID: tt.sid, DeviceID: tt.deviceID}})
			t.Cleanup(c.Close)
			if got := c.canResume(tt.resourceData); got != tt.want {
				t.Fatalf("canResume() = %t, want %t", got, tt.want)
			}
		})
	}
}
