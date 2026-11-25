package portscan

import (
	"errors"
	"testing"
)

func TestParseHostsErrors(t *testing.T) {
	tests := []struct {
		hosts []string
		want  error
	}{
		{nil, ErrNoHosts},
		{[]string{""}, ErrEmptyHost},
		{[]string{"   "}, ErrEmptyHost},
		{[]string{"bad host"}, ErrInvalidHost},
		{[]string{"[localhost]"}, ErrInvalidHost},
		{[]string{"[127.0.0.1]"}, ErrInvalidHost},
		{[]string{"my_host.test"}, ErrInvalidHost},
		{[]string{"999.1.1.1"}, ErrInvalidHost},
		{[]string{"1.2.3"}, ErrInvalidHost},
		{[]string{"a..b"}, ErrInvalidHost},
		{[]string{"-a.com"}, ErrInvalidHost},
		{[]string{"10.0.0.0/8"}, ErrInvalidHost},
		{[]string{"ok.example", ""}, ErrEmptyHost},
	}
	for _, tt := range tests {
		if _, err := parseHosts(tt.hosts); !errors.Is(err, tt.want) {
			t.Errorf("parseHosts(%q) = %v, want %v", tt.hosts, err, tt.want)
		}
	}
}

func TestParseHostsValidAndDedup(t *testing.T) {
	got, err := parseHosts([]string{
		"Example.COM", "example.com.", " example.com ",
		"192.168.1.1", "192.168.1.1",
		"::1", "[::1]", "::ffff:10.0.0.1", "10.0.0.1",
		"localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "192.168.1.1", "::1", "10.0.0.1", "localhost"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].name != w {
			t.Errorf("entry %d = %q, want %q", i, got[i].name, w)
		}
	}
}
