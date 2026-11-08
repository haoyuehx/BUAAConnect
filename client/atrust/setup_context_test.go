package atrust

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
)

type blockingUnderlayDialer struct{}

func (blockingUnderlayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingUnderlayDialer) ExcludeIP(net.IP) {}

func TestSetupContextCancellationReachesManifestDial(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(ctx, SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetupContext did not cancel in-flight manifest dial")
	}
}

func TestClientCloseCancelsSetupContext(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(context.Background(), SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not cancel in-flight setup")
	}
}

func TestSetupSessionContextOutlivesCallerContext(t *testing.T) {
	client := NewClient(ClientOptions{})
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()

	sessionCtx, finish := client.newSetupSessionContext(callerCtx)
	finish(true)
	cancelCaller()

	select {
	case <-sessionCtx.Done():
		t.Fatal("session context was cancelled with the setup caller after successful setup")
	case <-time.After(20 * time.Millisecond):
	}

	client.lifecycleCancel()
	select {
	case <-sessionCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("session context did not follow the client lifecycle")
	}
}

func TestSetupSessionContextCancelsWithCallerDuringSetup(t *testing.T) {
	client := NewClient(ClientOptions{})
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	sessionCtx, finish := client.newSetupSessionContext(callerCtx)
	defer finish(false)

	cancelCaller()
	select {
	case <-sessionCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("session context did not observe setup caller cancellation")
	}
}

func TestSetupSessionContextCancelsOnFailedSetup(t *testing.T) {
	client := NewClient(ClientOptions{})
	sessionCtx, finish := client.newSetupSessionContext(context.Background())
	finish(false)
	select {
	case <-sessionCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("failed setup did not cancel the session context")
	}
}

func TestRedactionHidesCredentials(t *testing.T) {
	secret := "super-secret-cookie-value"
	redacted := redactSecret("SID", secret)
	if strings.Contains(redacted, secret) {
		t.Fatalf("redacted value leaks the secret: %q", redacted)
	}
	if !strings.Contains(redacted, "redacted") || !strings.Contains(redacted, "SID") {
		t.Fatalf("redacted value = %q, want label and redaction marker", redacted)
	}

	summary := describeClientAuthData(auth.ClientAuthData{
		Cookies: []auth.Cookie{{Name: "sid", Value: secret}},
	})
	if strings.Contains(summary, secret) {
		t.Fatalf("auth data summary leaks a cookie: %q", summary)
	}
}
