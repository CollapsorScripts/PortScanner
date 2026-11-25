package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

func TestClassifyGeneric(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	bg := context.Background()

	tests := []struct {
		name   string
		parent context.Context
		err    error
		want   State
	}{
		{"canceled", bg, fmt.Errorf("dial: %w", context.Canceled), StateCanceled},
		{"deadline of port timeout", bg, context.DeadlineExceeded, StateTimeout},
		{"os deadline in OpError", bg, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, StateTimeout},
		{"deadline of user context", canceled, context.DeadlineExceeded, StateCanceled},
		{"other", bg, errors.New("boom"), StateError},
	}
	for _, tt := range tests {
		if got := classify(tt.parent, tt.err); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{
		StateOpen: "open", StateClosed: "closed", StateTimeout: "timeout",
		StateUnreachable: "unreachable", StateCanceled: "canceled",
		StateError: "error", State(0): "unknown",
	} {
		if s.String() != want {
			t.Errorf("State(%d).String() = %q, want %q", s, s.String(), want)
		}
	}
}
