package portscan

import "errors"

// Ошибки сканера. Для проверки используй errors.Is.
var (
	ErrNoHosts       = errors.New("portscan: no hosts specified")
	ErrEmptyHost     = errors.New("portscan: empty host")
	ErrInvalidHost   = errors.New("portscan: invalid host")
	ErrNoPorts       = errors.New("portscan: no ports specified")
	ErrInvalidPort   = errors.New("portscan: invalid port")
	ErrInvalidRange  = errors.New("portscan: invalid port range")
	ErrResolve       = errors.New("portscan: cannot resolve host")
	ErrInvalidOption = errors.New("portscan: invalid option")
)
