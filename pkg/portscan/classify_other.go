//go:build !unix && !windows

package portscan

func isRefused(error) bool     { return false }
func isUnreachable(error) bool { return false }
