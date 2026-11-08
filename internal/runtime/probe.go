package runtime

import (
	"net"
	"time"
)

// ProbeResult holds the result of a TCP connectivity probe.
type ProbeResult struct {
	Target   string
	Duration time.Duration
	Err      error
}

func probeConnectivity(target string, timeout time.Duration) ProbeResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return ProbeResult{Target: target, Duration: time.Since(start), Err: err}
	}
	_ = conn.Close()
	return ProbeResult{Target: target, Duration: time.Since(start)}
}
