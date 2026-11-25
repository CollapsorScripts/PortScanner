package portscan

import (
	"context"
	"errors"
	"net"
	"os"
)

// classify - определяет State по ошибке подключения. Текст ошибок не
// анализируется: используются errors.Is / errors.As и errno платформы.
func classify(parent context.Context, err error) State {
	switch {
	case errors.Is(err, context.Canceled):
		return StateCanceled
	case isTimeout(err):
		// Истёк дедлайн пользовательского контекста — это отмена, а не таймаут порта.
		if parent.Err() != nil {
			return StateCanceled
		}
		return StateTimeout
	case isRefused(err):
		return StateClosed
	case isUnreachable(err):
		return StateUnreachable
	default:
		return StateError
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
