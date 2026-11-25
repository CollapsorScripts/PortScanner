//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

// Коды Winsock: в пакете syscall под Windows одноимённые константы POSIX
// не совпадают с реальными кодами ошибок сокетов.
const (
	wsaENETDOWN     syscall.Errno = 10050
	wsaENETUNREACH  syscall.Errno = 10051
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

func isRefused(err error) bool { return errors.Is(err, wsaECONNREFUSED) }

func isUnreachable(err error) bool {
	return errors.Is(err, wsaENETUNREACH) ||
		errors.Is(err, wsaEHOSTUNREACH) ||
		errors.Is(err, wsaENETDOWN) ||
		errors.Is(err, wsaEHOSTDOWN)
}
