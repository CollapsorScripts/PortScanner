//go:build unix

package portscan

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyUnix(t *testing.T) {
	wrap := func(e syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
	}
	bg := context.Background()
	tests := []struct {
		errno syscall.Errno
		want  State
	}{
		{syscall.ECONNREFUSED, StateClosed},
		{syscall.ENETUNREACH, StateUnreachable},
		{syscall.EHOSTUNREACH, StateUnreachable},
		{syscall.ECONNRESET, StateError},
		{syscall.ETIMEDOUT, StateTimeout},
	}
	for _, tt := range tests {
		if got := classify(bg, wrap(tt.errno)); got != tt.want {
			t.Errorf("%v: got %s, want %s", tt.errno, got, tt.want)
		}
	}
}
