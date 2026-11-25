package portscan

import (
	"errors"
	"slices"
	"testing"
)

func TestPortSetNormalization(t *testing.T) {
	s := Union(Ports(80, 22, 80), Range(20, 25), Range(26, 30))
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	if s.Len() != 12 { // 20..30 и отдельно 80
		t.Errorf("Len = %d, want 12", s.Len())
	}
	if !slices.Equal(s.ranges, []portRange{{20, 30}, {80, 80}}) {
		t.Errorf("ranges not merged: %v", s.ranges)
	}
	var got []uint16
	for p := range s.all() {
		got = append(got, p)
	}
	if !slices.Equal(got, []uint16{20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 80}) {
		t.Errorf("unexpected iteration: %v", got)
	}
}

func TestPortSetErrors(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want error
	}{
		{"zero port", Ports(0), ErrInvalidPort},
		{"negative", Ports(-1), ErrInvalidPort},
		{"too big", Ports(65536), ErrInvalidPort},
		{"range too big", Range(1, 70000), ErrInvalidPort},
		{"range zero", Range(0, 10), ErrInvalidPort},
		{"reversed", Range(1000, 1), ErrInvalidRange},
		{"union keeps error", Union(Ports(80), Ports(0)), ErrInvalidPort},
	}
	for _, tt := range tests {
		if !errors.Is(tt.set.Err(), tt.want) {
			t.Errorf("%s: Err = %v, want %v", tt.name, tt.set.Err(), tt.want)
		}
	}
	if Range(1, 65535).Len() != 65535 {
		t.Error("full range must contain 65535 ports")
	}
}

func TestParsePorts(t *testing.T) {
	s, err := ParsePorts("22, 80,8000-8002")
	if err != nil || s.Len() != 5 {
		t.Fatalf("ParsePorts: len=%d err=%v", s.Len(), err)
	}
	for spec, want := range map[string]error{
		"":       ErrNoPorts,
		"  ":     ErrNoPorts,
		"abc":    ErrInvalidPort,
		"1,,2":   ErrInvalidPort,
		"0":      ErrInvalidPort,
		"70000":  ErrInvalidPort,
		"1-b":    ErrInvalidPort,
		"1000-1": ErrInvalidRange,
	} {
		if _, err := ParsePorts(spec); !errors.Is(err, want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", spec, err, want)
		}
	}
}
