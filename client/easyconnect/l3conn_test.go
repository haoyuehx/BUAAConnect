package easyconnect

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

var errL3ReadFailed = errors.New("l3 read failed")
var errL3WriteFailed = errors.New("l3 write failed")

type failingReadCloser struct {
	err    error
	closes atomic.Int32
}

func (c *failingReadCloser) Read([]byte) (int, error) { return 0, c.err }

func (c *failingReadCloser) Close() error {
	c.closes.Add(1)
	return nil
}

type failingWriteCloser struct {
	err    error
	closes atomic.Int32
}

func (c *failingWriteCloser) Write([]byte) (int, error) { return 0, c.err }

func (c *failingWriteCloser) Close() error {
	c.closes.Add(1)
	return nil
}

func newReconnectTestClient(parent context.Context, maxReconnect int, delay time.Duration) *Client {
	return &Client{
		lifecycleCtx:   parent,
		maxReconnect:   maxReconnect,
		reconnectDelay: delay,
	}
}

func TestL3ReconnectLimitDefaultsAndOverrides(t *testing.T) {
	if got := (*Client)(nil).l3ReconnectLimit(); got != defaultL3ReconnectLimit {
		t.Fatalf("nil client limit = %d, want %d", got, defaultL3ReconnectLimit)
	}
	if got := (&Client{}).l3ReconnectLimit(); got != defaultL3ReconnectLimit {
		t.Fatalf("zero-value limit = %d, want %d", got, defaultL3ReconnectLimit)
	}
	if got := (&Client{maxReconnect: 2}).l3ReconnectLimit(); got != 2 {
		t.Fatalf("configured limit = %d, want 2", got)
	}
}

func TestL3ReconnectDelayBacksOffAndCaps(t *testing.T) {
	client := &Client{reconnectDelay: time.Second}
	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}
	for attempt, expected := range want {
		if got := client.l3ReconnectDelay(attempt); got != expected {
			t.Fatalf("l3ReconnectDelay(%d) = %s, want %s", attempt, got, expected)
		}
	}

	// A configured delay larger than the cap is honoured as-is and never
	// shortened by the backoff logic.
	slow := &Client{reconnectDelay: time.Minute}
	if got := slow.l3ReconnectDelay(3); got != time.Minute {
		t.Fatalf("slow l3ReconnectDelay(3) = %s, want %s", got, time.Minute)
	}

	// A bare client falls back to the default base delay.
	if got := (*Client)(nil).l3ReconnectDelay(0); got != defaultL3ReconnectDelay {
		t.Fatalf("nil client delay = %s, want %s", got, defaultL3ReconnectDelay)
	}
}

func TestL3ConnReadStopsAfterMaxReconnect(t *testing.T) {
	client := newReconnectTestClient(context.Background(), 2, time.Millisecond)
	recv := &failingReadCloser{err: errL3ReadFailed}
	conn := &L3Conn{easyConnectClient: client, recvConn: recv}

	// A nil token makes RecvConn fail without touching the network, so the
	// reconnect attempts are observable through their error.
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := conn.Read(make([]byte, 1))
		if err == nil || !containsTokenError(err) {
			t.Fatalf("Read() attempt %d error = %v, want re-handshake token error", attempt, err)
		}
	}
	if got := conn.recvErrCount; got != 2 {
		t.Fatalf("recvErrCount = %d, want 2", got)
	}

	// The failure budget is exhausted: Read must surface the transport error
	// instead of re-handshaking again.
	_, err := conn.Read(make([]byte, 1))
	if !errors.Is(err, errL3ReadFailed) {
		t.Fatalf("Read() after budget error = %v, want %v", err, errL3ReadFailed)
	}
	if got := conn.recvErrCount; got != 2 {
		t.Fatalf("recvErrCount after budget = %d, want 2", got)
	}
}

func TestL3ConnWriteStopsAfterMaxReconnect(t *testing.T) {
	client := newReconnectTestClient(context.Background(), 2, time.Millisecond)
	send := &failingWriteCloser{err: errL3WriteFailed}
	conn := &L3Conn{easyConnectClient: client, sendConn: send}

	for attempt := 1; attempt <= 2; attempt++ {
		_, err := conn.Write([]byte("packet"))
		if err == nil || !containsTokenError(err) {
			t.Fatalf("Write() attempt %d error = %v, want re-handshake token error", attempt, err)
		}
	}
	if _, err := conn.Write([]byte("packet")); !errors.Is(err, errL3WriteFailed) {
		t.Fatalf("Write() after budget error = %v, want %v", err, errL3WriteFailed)
	}
}

func TestL3ConnReadReconnectAbortsOnClientClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := newReconnectTestClient(ctx, 5, time.Hour)
	conn := &L3Conn{easyConnectClient: client, recvConn: &failingReadCloser{err: errL3ReadFailed}}

	result := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		result <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Read() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read() did not abort the reconnect backoff after client close")
	}
}

func TestL3ConnWriteReconnectAbortsOnClientClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := newReconnectTestClient(ctx, 5, time.Hour)
	conn := &L3Conn{easyConnectClient: client, sendConn: &failingWriteCloser{err: errL3WriteFailed}}

	result := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("packet"))
		result <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Write() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write() did not abort the reconnect backoff after client close")
	}
}

func containsTokenError(err error) bool {
	return err != nil && err.Error() == "token is nil"
}
