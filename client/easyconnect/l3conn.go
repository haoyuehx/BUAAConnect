package easyconnect

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const (
	// defaultL3ReconnectLimit matches the historical hard-coded budget of 5
	// consecutive failed re-handshakes.
	defaultL3ReconnectLimit = 5
	// defaultL3ReconnectDelay is the first backoff step between re-handshakes.
	defaultL3ReconnectDelay = time.Second
	// maxL3ReconnectDelay caps exponential backoff so a long outage does not
	// stall the tunnel for minutes.
	maxL3ReconnectDelay = 30 * time.Second
)

type L3Conn struct {
	easyConnectClient *Client

	sendConn     io.WriteCloser
	sendLock     sync.Mutex
	sendErrCount int

	recvConn     io.ReadCloser
	recvLock     sync.Mutex
	recvErrCount int
}

// l3ReconnectLimit returns the configured consecutive-failure budget. A client
// built without NewClient still gets the historical default.
func (c *Client) l3ReconnectLimit() int {
	if c == nil || c.maxReconnect <= 0 {
		return defaultL3ReconnectLimit
	}
	return c.maxReconnect
}

// l3ReconnectDelay returns the exponential backoff before the given reconnect
// attempt (0 = first retry). The configured delay is the base step and values
// above the cap are honoured as-is rather than being shortened.
func (c *Client) l3ReconnectDelay(attempt int) time.Duration {
	base := defaultL3ReconnectDelay
	if c != nil && c.reconnectDelay > 0 {
		base = c.reconnectDelay
	}
	if attempt < 0 {
		attempt = 0
	}
	limit := maxL3ReconnectDelay
	if base > limit {
		limit = base
	}
	delay := base
	for i := 0; i < attempt; i++ {
		if delay >= limit/2 {
			return limit
		}
		delay *= 2
	}
	return delay
}

// waitL3Reconnect sleeps for the backoff delay or returns early when the
// client lifecycle is cancelled. Without a lifecycle (tests constructing a
// bare Client) only the timer is used.
func (c *Client) waitL3Reconnect(attempt int) error {
	delay := c.l3ReconnectDelay(attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	var done <-chan struct{}
	if c != nil && c.lifecycleCtx != nil {
		done = c.lifecycleCtx.Done()
	}
	select {
	case <-timer.C:
		return nil
	case <-done:
		return c.lifecycleErr()
	}
}

func (c *Client) lifecycleErr() error {
	if c == nil || c.lifecycleCtx == nil {
		return context.Canceled
	}
	if err := c.lifecycleCtx.Err(); err != nil {
		return err
	}
	return context.Canceled
}

// try best to read, if return err!=nil, please panic
func (c *L3Conn) Read(p []byte) (n int, err error) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()
	for {
		n, err = c.recvConn.Read(p)
		if err == nil {
			c.recvErrCount = 0
			return n, nil
		}

		// The server explicitly shut the session down. Re-handshaking cannot
		// fix this and only delays the caller's cleanup path.
		if errors.Is(err, ErrSangforShutdown) {
			return 0, err
		}
		if c.recvErrCount >= c.easyConnectClient.l3ReconnectLimit() {
			return 0, err
		}

		log.Printf("Error occurred while receiving, retrying: %v", err)

		// Do handshake again and create a new recvConn. The broken connection
		// is closed before backing off so its socket does not linger.
		_ = c.recvConn.Close()
		if waitErr := c.easyConnectClient.waitL3Reconnect(c.recvErrCount); waitErr != nil {
			return 0, waitErr
		}
		newConn, reconnectErr := c.easyConnectClient.RecvConn()
		if reconnectErr != nil {
			if errors.Is(reconnectErr, ErrSangforShutdown) {
				return 0, reconnectErr
			}
			c.recvErrCount++
			return 0, reconnectErr
		}
		c.recvConn = newConn
		// A successful re-handshake starts a fresh error budget.
		c.recvErrCount = 0
	}
}

// try best to write, if return err!=nil, please panic
func (c *L3Conn) Write(p []byte) (n int, err error) {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()
	for {
		n, err = c.sendConn.Write(p)
		if err == nil {
			c.sendErrCount = 0
			return n, nil
		}

		// Server-initiated SHUTDOWN (sangfor cmd 0x08) is terminal; retrying
		// the handshake would loop until the process is killed.
		if errors.Is(err, ErrSangforShutdown) {
			return 0, err
		}
		if c.sendErrCount >= c.easyConnectClient.l3ReconnectLimit() {
			return 0, err
		}

		log.Printf("Error occurred while sending, retrying: %v", err)

		// Do handshake again and create a new sendConn.
		_ = c.sendConn.Close()
		if waitErr := c.easyConnectClient.waitL3Reconnect(c.sendErrCount); waitErr != nil {
			return 0, waitErr
		}
		newConn, reconnectErr := c.easyConnectClient.SendConn()
		if reconnectErr != nil {
			// SendConn surfaces SHUTDOWN here; never mask it behind a retry.
			if errors.Is(reconnectErr, ErrSangforShutdown) {
				return 0, reconnectErr
			}
			c.sendErrCount++
			return 0, reconnectErr
		}
		c.sendConn = newConn
		// A successful re-handshake starts a fresh error budget.
		c.sendErrCount = 0
	}
}

func (c *L3Conn) Close() error {
	if c.sendConn != nil {
		_ = c.sendConn.Close()
	}
	if c.recvConn != nil {
		_ = c.recvConn.Close()
	}
	return nil
}

func (c *Client) NewL3Conn() (io.ReadWriteCloser, error) {
	conn := &L3Conn{
		easyConnectClient: c,
		sendErrCount:      0,
		recvErrCount:      0,
	}

	var err error
	conn.sendConn, err = c.SendConn()
	if err != nil {
		log.Printf("Error occurred while creating sendConn: %v", err)
		return nil, err
	}

	conn.recvConn, err = c.RecvConn()
	if err != nil {
		log.Printf("Error occurred while creating recvConn: %v", err)
		_ = conn.sendConn.Close()
		return nil, err
	}
	return conn, nil
}
