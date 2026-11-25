package portscan

import (
	"net"
	"time"
)

// Result - результат проверки одного порта.
type Result struct {
	// Host - нормализованное имя или IP из списка целей.
	Host string
	// IP - проверенный адрес. При ошибке DNS остаётся nil.
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	// Err - ошибка подключения или DNS. У открытого порта равна nil.
	Err error
}
