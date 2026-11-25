package portscan

import (
	"fmt"
	"net/netip"
	"strings"
)

type hostEntry struct {
	name string     // нормализованное имя (для IP — каноничная запись)
	addr netip.Addr // заполнено, если isIP
	isIP bool
}

// parseHosts - валидирует цели синтаксически (без обращения к сети) и убирает
// повторы. Первая же ошибка прерывает разбор.
func parseHosts(hosts []string) ([]hostEntry, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}
	entries := make([]hostEntry, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for i, raw := range hosts {
		e, err := parseHost(raw)
		if err != nil {
			return nil, fmt.Errorf("host #%d %q: %w", i, raw, err)
		}
		if _, dup := seen[e.name]; dup {
			continue
		}
		seen[e.name] = struct{}{}
		entries = append(entries, e)
	}
	return entries, nil
}

func parseHost(raw string) (hostEntry, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return hostEntry{}, ErrEmptyHost
	}
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		addr, err := netip.ParseAddr(h[1 : len(h)-1])
		if err != nil || !addr.Is6() {
			return hostEntry{}, ErrInvalidHost
		}
		h = addr.String()
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = addr.Unmap()
		return hostEntry{name: addr.String(), addr: addr, isIP: true}, nil
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if !validHostname(h) {
		return hostEntry{}, ErrInvalidHost
	}
	return hostEntry{name: h}, nil
}

// validHostname - проверяет имя по правилам RFC 1123 (ASCII). Имя, у которого
// последняя метка состоит только из цифр, считается испорченным IP-адресом
// (например, "999.1.1.1"), а не DNS-именем.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
			if !ok {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return true
		}
	}
	return false
}
