package portscan

import (
	"fmt"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = 2 * time.Second
)

type config struct {
	concurrency int
	timeout     time.Duration
	buffer      int
	dialer      Dialer
	resolver    Resolver
}

// Option - настраивает Scanner в New.
type Option func(*config) error

// WithConcurrency - задаёт максимум одновременных подключений (по умолчанию 100).
// Лимит общий для всех вызовов Scan одного сканера. n должно быть >= 1.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: concurrency must be >= 1, got %d", ErrInvalidOption, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout - задаёт таймаут одного подключения (по умолчанию 2s). d должно быть > 0.
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be > 0, got %s", ErrInvalidOption, d)
		}
		c.timeout = d
		return nil
	}
}

// WithResultBuffer - задаёт размер буфера канала результатов (по умолчанию равен
// concurrency). 0 — небуферизованный канал: сканирование идёт со скоростью читателя.
func WithResultBuffer(n int) Option {
	return func(c *config) error {
		if n < 0 {
			return fmt.Errorf("%w: result buffer must be >= 0, got %d", ErrInvalidOption, n)
		}
		c.buffer = n
		return nil
	}
}

// WithDialer - подменяет способ установки соединений (прокси, тесты).
func WithDialer(d Dialer) Option {
	return func(c *config) error {
		if d == nil {
			return fmt.Errorf("%w: dialer is nil", ErrInvalidOption)
		}
		c.dialer = d
		return nil
	}
}

// WithResolver - подменяет DNS-резолвер (по умолчанию net.DefaultResolver).
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if r == nil {
			return fmt.Errorf("%w: resolver is nil", ErrInvalidOption)
		}
		c.resolver = r
		return nil
	}
}
