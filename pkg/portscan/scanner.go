package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Scanner - сканер с общим лимитом подключений для всех вызовов Scan.
// Один экземпляр можно использовать из нескольких горутин.
type Scanner struct {
	concurrency int
	timeout     time.Duration
	buffer      int
	dialer      Dialer
	resolver    Resolver
	sem         chan struct{} // общий лимит одновременных подключений
}

type job struct {
	host string
	addr netip.Addr
	port uint16
}

// New - создаёт сканер с заданными опциями.
func New(opts ...Option) (*Scanner, error) {
	c := config{
		concurrency: defaultConcurrency,
		timeout:     defaultConnectTimeout,
		buffer:      -1,
		dialer:      &net.Dialer{},
		resolver:    net.DefaultResolver,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&c); err != nil {
			return nil, err
		}
	}
	if c.buffer < 0 {
		c.buffer = c.concurrency
	}
	return &Scanner{
		concurrency: c.concurrency,
		timeout:     c.timeout,
		buffer:      c.buffer,
		dialer:      c.dialer,
		resolver:    c.resolver,
		sem:         make(chan struct{}, c.concurrency),
	}, nil
}

// Scan - запускает проверку хостов и возвращает канал результатов.
// Ошибки DNS приходят в Result.Err. После отмены ctx канал можно не дочитывать.
// Порядок результатов зависит от времени подключения.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ports.err != nil {
		return nil, ports.err
	}
	if len(ports.ranges) == 0 {
		return nil, ErrNoPorts
	}
	entries, err := parseHosts(hosts)
	if err != nil {
		return nil, err
	}
	out := make(chan Result, s.buffer)
	go s.run(ctx, entries, ports, out)
	return out, nil
}

func (s *Scanner) run(ctx context.Context, entries []hostEntry, ports PortSet, out chan<- Result) {
	defer close(out)

	jobs := make(chan job)
	var wg sync.WaitGroup
	wg.Add(s.concurrency)
	for range s.concurrency {
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, out)
		}()
	}

	s.produce(ctx, entries, ports, jobs, out)
	close(jobs)
	wg.Wait()
}

// produce - разрешает имена и передаёт порты воркерам без накопления заданий.
func (s *Scanner) produce(ctx context.Context, entries []hostEntry, ports PortSet, jobs chan<- job, out chan<- Result) {
	seen := make(map[netip.Addr]struct{})
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		addrs, err := s.resolve(ctx, e)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			for port := range ports.all() {
				if !emit(ctx, out, Result{Host: e.name, Port: port, State: StateError, Err: err}) {
					return
				}
			}
			continue
		}
		for _, addr := range addrs {
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			for port := range ports.all() {
				if ctx.Err() != nil {
					return
				}
				select {
				case jobs <- job{host: e.name, addr: addr, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (s *Scanner) resolve(ctx context.Context, e hostEntry) ([]netip.Addr, error) {
	if e.isIP {
		return []netip.Addr{e.addr}, nil
	}
	found, err := s.resolver.LookupNetIP(ctx, "ip", e.name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrResolve, e.name, err)
	}
	addrs := make([]netip.Addr, 0, len(found))
	for _, a := range found {
		a = a.Unmap()
		if !a.IsValid() || slices.Contains(addrs, a) {
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %s: no addresses", ErrResolve, e.name)
	}
	return addrs, nil
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan job, out chan<- Result) {
	for j := range jobs {
		if !s.acquire(ctx) {
			continue // ctx отменён: задание не запускаем, но продолжаем опустошать канал
		}
		r := s.probe(ctx, j)
		s.release()
		emit(ctx, out, r)
	}
}

func (s *Scanner) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case s.sem <- struct{}{}:
		// Отмена могла прийти одновременно с освобождением слота.
		if ctx.Err() != nil {
			s.release()
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Scanner) release() { <-s.sem }

func (s *Scanner) probe(ctx context.Context, j job) Result {
	res := Result{Host: j.host, IP: net.IP(j.addr.AsSlice()), Port: j.port}
	address := net.JoinHostPort(j.addr.String(), strconv.Itoa(int(j.port)))

	start := time.Now()
	dctx, cancel := context.WithTimeout(ctx, s.timeout)
	conn, err := s.dialer.DialContext(dctx, "tcp", address)
	cancel()
	res.Duration = time.Since(start)

	if err != nil {
		res.State = classify(ctx, err)
		res.Err = err
		return res
	}
	_ = conn.Close()
	res.State = StateOpen
	return res
}

// emit - отправляет результат, пока читатель готов или контекст не отменён.
func emit(ctx context.Context, out chan<- Result, r Result) bool {
	select {
	case out <- r:
		return true
	default:
	}
	select {
	case out <- r:
		return true
	case <-ctx.Done():
		return false
	}
}
