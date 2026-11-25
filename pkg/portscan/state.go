package portscan

// State - итог проверки одного порта.
type State uint8

const (
	// StateOpen — TCP-соединение установлено.
	StateOpen State = iota + 1
	// StateClosed — соединение явно отклонено (RST / connection refused).
	StateClosed
	// StateTimeout — подключение не завершилось за WithConnectTimeout.
	StateTimeout
	// StateUnreachable — узел или сеть недоступны.
	StateUnreachable
	// StateCanceled — проверка прервана отменой context.Context.
	StateCanceled
	// StateError — любая другая ошибка (в том числе ошибка резолвинга имени).
	StateError
)

// String - возвращает короткое имя состояния; для нулевого значения — "unknown".
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// MarshalText - позволяет сериализовать состояние в JSON и другие текстовые форматы.
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }
