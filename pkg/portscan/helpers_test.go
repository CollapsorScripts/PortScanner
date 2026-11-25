package portscan

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDialer имитирует сеть: считает вызовы, пиковую параллельность и закрытия.
type fakeDialer struct {
	delay  time.Duration
	calls  atomic.Int64
	opened atomic.Int64
	closed atomic.Int64
	cur    atomic.Int64
	peak   atomic.Int64
}

func (d *fakeDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.calls.Add(1)
	n := d.cur.Add(1)
	defer d.cur.Add(-1)
	for {
		p := d.peak.Load()
		if n <= p || d.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if d.delay > 0 {
		select {
		case <-time.After(d.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	a, b := net.Pipe()
	_ = b.Close()
	d.opened.Add(1)
	return &trackConn{Conn: a, closed: &d.closed}, nil
}

type trackConn struct {
	net.Conn
	closed *atomic.Int64
}

func (c *trackConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

// collect читает канал до закрытия; безопасен для вызова из других горутин.
func collect(t *testing.T, ch <-chan Result) []Result {
	t.Helper()
	var out []Result
	timeout := time.After(10 * time.Second)
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, r)
		case <-timeout:
			t.Error("timed out waiting for the results channel to close")
			return out
		}
	}
}

func mustNew(t *testing.T, opts ...Option) *Scanner {
	t.Helper()
	s, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}
