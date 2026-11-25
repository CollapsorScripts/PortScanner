package portscan

import (
	"context"
	"net"
	"net/netip"
)

// Dialer - устанавливает исходящие соединения. *net.Dialer ему удовлетворяет.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver - превращает DNS-имя в IP-адреса. *net.Resolver ему удовлетворяет.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}
