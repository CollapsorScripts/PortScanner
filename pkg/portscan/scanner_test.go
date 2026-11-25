package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestNewInvalidOptions(t *testing.T) {
	for i, opt := range []Option{
		WithConcurrency(0), WithConcurrency(-1),
		WithConnectTimeout(0), WithConnectTimeout(-time.Second),
		WithResultBuffer(-1), WithDialer(nil), WithResolver(nil),
	} {
		if _, err := New(opt); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("option #%d: err = %v, want ErrInvalidOption", i, err)
		}
	}
	if _, err := New(); err != nil {
		t.Errorf("New() with defaults: %v", err)
	}
}

func TestScanArgumentValidation(t *testing.T) {
	s := mustNew(t, WithDialer(&fakeDialer{}))
	ctx := context.Background()
	tests := []struct {
		name  string
		hosts []string
		ports PortSet
		want  error
	}{
		{"no hosts", nil, Ports(80), ErrNoHosts},
		{"empty host", []string{""}, Ports(80), ErrEmptyHost},
		{"invalid host", []string{"bad host"}, Ports(80), ErrInvalidHost},
		{"no ports", []string{"10.0.0.1"}, Ports(), ErrNoPorts},
		{"zero value ports", []string{"10.0.0.1"}, PortSet{}, ErrNoPorts},
		{"port 0", []string{"10.0.0.1"}, Ports(0), ErrInvalidPort},
		{"port 65536", []string{"10.0.0.1"}, Ports(65536), ErrInvalidPort},
		{"reversed", []string{"10.0.0.1"}, Range(1000, 1), ErrInvalidRange},
	}
	for _, tt := range tests {
		ch, err := s.Scan(ctx, tt.hosts, tt.ports)
		if !errors.Is(err, tt.want) || ch != nil {
			t.Errorf("%s: ch=%v err=%v, want %v", tt.name, ch, err, tt.want)
		}
	}
}

func TestScanContextAlreadyCanceled(t *testing.T) {
	d := &fakeDialer{}
	s := mustNew(t, WithDialer(d))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, []string{"10.0.0.1"}, Ports(80)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if d.calls.Load() != 0 {
		t.Error("no dial expected")
	}
}

func TestScanLoopbackOpenAndClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	closedPort := tmp.Addr().(*net.TCPAddr).Port
	_ = tmp.Close()

	s := mustNew(t, WithConnectTimeout(2*time.Second))
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, Ports(openPort, closedPort))
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]Result{}
	for _, r := range collect(t, ch) {
		got[int(r.Port)] = r
	}
	if r := got[openPort]; r.State != StateOpen || r.Err != nil || !r.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("open port: %+v", r)
	}
	if r := got[closedPort]; r.State != StateClosed || r.Err == nil {
		t.Errorf("closed port: %+v", r)
	}
}

func TestConcurrencyLimitAndConnectionsClosed(t *testing.T) {
	d := &fakeDialer{delay: 2 * time.Millisecond}
	s := mustNew(t, WithConcurrency(5), WithDialer(d))
	ch, err := s.Scan(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, Range(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	res := collect(t, ch)
	if len(res) != 200 {
		t.Fatalf("got %d results, want 200", len(res))
	}
	for _, r := range res {
		if r.State != StateOpen {
			t.Fatalf("unexpected result %+v", r)
		}
	}
	if p := d.peak.Load(); p > 5 || p < 2 {
		t.Errorf("peak concurrency = %d, want 2..5", p)
	}
	if d.opened.Load() != 200 || d.closed.Load() != 200 {
		t.Errorf("opened=%d closed=%d, want 200/200", d.opened.Load(), d.closed.Load())
	}
}

func TestTimeoutState(t *testing.T) {
	d := &fakeDialer{delay: time.Hour}
	s := mustNew(t, WithConnectTimeout(20*time.Millisecond), WithDialer(d))
	ch, err := s.Scan(context.Background(), []string{"10.0.0.1"}, Ports(80))
	if err != nil {
		t.Fatal(err)
	}
	res := collect(t, ch)
	if len(res) != 1 || res[0].State != StateTimeout || !errors.Is(res[0].Err, context.DeadlineExceeded) {
		t.Fatalf("got %+v", res)
	}
	if res[0].Duration < 15*time.Millisecond {
		t.Errorf("Duration = %s", res[0].Duration)
	}
}

func TestCancelStopsNewDialsAndClosesChannel(t *testing.T) {
	d := &fakeDialer{delay: time.Hour}
	s := mustNew(t, WithConcurrency(4), WithDialer(d))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := s.Scan(ctx, []string{"10.0.0.1"}, Range(1, 65535))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()

	res := collect(t, ch)
	if len(res) > 4 {
		t.Errorf("got %d results, want <= 4 (only in-flight probes)", len(res))
	}
	for _, r := range res {
		if r.State != StateCanceled {
			t.Errorf("unexpected state %s", r.State)
		}
	}
	if c := d.calls.Load(); c > 4 {
		t.Errorf("dials = %d, want <= 4", c)
	}
}

func TestAbandonedReaderDoesNotLeakGoroutines(t *testing.T) {
	base := runtime.NumGoroutine()
	d := &fakeDialer{}
	s := mustNew(t, WithConcurrency(8), WithResultBuffer(0), WithDialer(d))
	ctx, cancel := context.WithCancel(context.Background())

	if _, err := s.Scan(ctx, []string{"10.0.0.1"}, Range(1, 1000)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // никто не читает канал
	cancel()

	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Errorf("goroutines: %d, base %d", n, base)
	}
}

func TestSlowReaderLosesNothing(t *testing.T) {
	s := mustNew(t, WithConcurrency(8), WithResultBuffer(0), WithDialer(&fakeDialer{}))
	ch, err := s.Scan(context.Background(), []string{"10.0.0.1"}, Range(1, 200))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range ch {
		n++
		time.Sleep(100 * time.Microsecond)
	}
	if n != 200 {
		t.Errorf("got %d results, want 200", n)
	}
}

func TestResolveMultipleIPsDuplicatesAndFailures(t *testing.T) {
	ip := netip.MustParseAddr
	resolver := resolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "multi.test":
			return []netip.Addr{ip("10.0.0.2"), ip("10.0.0.3"), ip("10.0.0.2"), ip("::ffff:10.0.0.3")}, nil
		case "empty.test":
			return nil, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})
	s := mustNew(t, WithDialer(&fakeDialer{}), WithResolver(resolver))

	hosts := []string{"multi.test", "MULTI.test.", "nx.test", "empty.test", "10.0.0.1", "10.0.0.1", "10.0.0.2"}
	ch, err := s.Scan(context.Background(), hosts, Ports(80, 81))
	if err != nil {
		t.Fatal(err)
	}
	perHost := map[string]int{}
	ips := map[string]bool{}
	for _, r := range collect(t, ch) {
		perHost[r.Host]++
		switch r.Host {
		case "nx.test", "empty.test":
			if r.State != StateError || !errors.Is(r.Err, ErrResolve) || r.IP != nil {
				t.Errorf("resolve failure result: %+v", r)
			}
		default:
			if r.State != StateOpen {
				t.Errorf("unexpected %+v", r)
			}
			ips[r.IP.String()] = true
		}
	}
	// multi.test: 2 адреса × 2 порта; nx/empty: по 2 ошибки; 10.0.0.1: 2;
	// литерал 10.0.0.2 уже просканирован как адрес multi.test.
	want := map[string]int{"multi.test": 4, "nx.test": 2, "empty.test": 2, "10.0.0.1": 2}
	for h, n := range want {
		if perHost[h] != n {
			t.Errorf("host %s: %d results, want %d", h, perHost[h], n)
		}
	}
	if len(perHost) != len(want) {
		t.Errorf("unexpected hosts: %v", perHost)
	}
	for _, a := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if !ips[a] {
			t.Errorf("address %s was not scanned", a)
		}
	}
}

func TestScannerReuseAndSharedLimit(t *testing.T) {
	d := &fakeDialer{delay: time.Millisecond}
	s := mustNew(t, WithConcurrency(5), WithDialer(d))

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := s.Scan(context.Background(), []string{"10.0.0.1"}, Range(1, 50))
			if err != nil {
				t.Error(err)
				return
			}
			if n := len(collect(t, ch)); n != 50 {
				t.Errorf("got %d results, want 50", n)
			}
		}()
	}
	wg.Wait()
	if p := d.peak.Load(); p > 5 {
		t.Errorf("peak concurrency across scans = %d, want <= 5", p)
	}

	// Повторный последовательный запуск того же сканера.
	ch, err := s.Scan(context.Background(), []string{"10.0.0.9"}, Ports(1, 2, 3))
	if err != nil || len(collect(t, ch)) != 3 {
		t.Errorf("second scan failed: %v", err)
	}
}
