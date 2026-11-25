//go:build unix

package main

import "syscall"

func init() {
	signals = append(signals, syscall.SIGTERM)
}
