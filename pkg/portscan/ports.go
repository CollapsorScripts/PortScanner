package portscan

import (
	"cmp"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
)

const maxPort = 65535

type portRange struct{ from, to int }

// PortSet - набор портов без повторов. Нулевое значение означает пустой набор.
// Ошибку построения возвращает Err или Scanner.Scan.
type PortSet struct {
	ranges []portRange
	err    error
}

// Ports - создаёт множество из отдельных портов. Порт вне 1–65535 даёт ErrInvalidPort.
func Ports(ports ...int) PortSet {
	rs := make([]portRange, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > maxPort {
			return PortSet{err: fmt.Errorf("%w: %d (allowed 1-%d)", ErrInvalidPort, p, maxPort)}
		}
		rs = append(rs, portRange{p, p})
	}
	return PortSet{ranges: normalize(rs)}
}

// Range - создаёт диапазон портов [from, to] включительно.
// Порт вне 1–65535 даёт ErrInvalidPort, обратный диапазон (from > to) — ErrInvalidRange.
func Range(from, to int) PortSet {
	for _, p := range [...]int{from, to} {
		if p < 1 || p > maxPort {
			return PortSet{err: fmt.Errorf("%w: %d (allowed 1-%d)", ErrInvalidPort, p, maxPort)}
		}
	}
	if from > to {
		return PortSet{err: fmt.Errorf("%w: %d-%d", ErrInvalidRange, from, to)}
	}
	return PortSet{ranges: []portRange{{from, to}}}
}

// Union - объединяет несколько множеств. Если хотя бы одно содержит ошибку,
// результат содержит первую из них.
func Union(sets ...PortSet) PortSet {
	var all []portRange
	for _, s := range sets {
		if s.err != nil {
			return PortSet{err: s.err}
		}
		all = append(all, s.ranges...)
	}
	return PortSet{ranges: normalize(all)}
}

// ParsePorts - разбирает строку вида "22,80,8000-8100".
func ParsePorts(spec string) (PortSet, error) {
	if strings.TrimSpace(spec) == "" {
		return PortSet{}, ErrNoPorts
	}
	var sets []PortSet
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return PortSet{}, fmt.Errorf("%w: empty element in %q", ErrInvalidPort, spec)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return PortSet{}, fmt.Errorf("%w: %q", ErrInvalidPort, lo)
		}
		set := Ports(a)
		if isRange {
			b, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil {
				return PortSet{}, fmt.Errorf("%w: %q", ErrInvalidPort, hi)
			}
			set = Range(a, b)
		}
		if set.err != nil {
			return PortSet{}, set.err
		}
		sets = append(sets, set)
	}
	return Union(sets...), nil
}

// Len - возвращает количество уникальных портов в множестве.
func (s PortSet) Len() int {
	n := 0
	for _, r := range s.ranges {
		n += r.to - r.from + 1
	}
	return n
}

// Err - возвращает ошибку, накопленную при построении множества.
func (s PortSet) Err() error { return s.err }

// all - лениво перебирает порты по возрастанию.
func (s PortSet) all() iter.Seq[uint16] {
	return func(yield func(uint16) bool) {
		for _, r := range s.ranges {
			for p := r.from; p <= r.to; p++ {
				if !yield(uint16(p)) {
					return
				}
			}
		}
	}
}

// normalize - сортирует диапазоны и склеивает пересекающиеся и соседние.
func normalize(rs []portRange) []portRange {
	if len(rs) == 0 {
		return nil
	}
	sorted := slices.Clone(rs)
	slices.SortFunc(sorted, func(a, b portRange) int { return cmp.Compare(a.from, b.from) })
	out := make([]portRange, 0, len(sorted))
	out = append(out, sorted[0])
	for _, r := range sorted[1:] {
		last := &out[len(out)-1]
		if r.from <= last.to+1 {
			last.to = max(last.to, r.to)
		} else {
			out = append(out, r)
		}
	}
	return out
}
