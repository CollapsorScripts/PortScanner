package app

import (
	"context"
	"errors"
	"fmt"
	"io"

	"portscanner/internal/config"
	"portscanner/pkg/portscan"
)

// Run - запускает сканирование и пишет результаты по мере готовности.
func Run(ctx context.Context, cfg config.Config, output, diagnostics io.Writer) error {
	scanner, err := portscan.New(
		portscan.WithConcurrency(cfg.Concurrency),
		portscan.WithConnectTimeout(cfg.Timeout),
	)
	if err != nil {
		return err
	}
	// Ошибка записи тоже должна остановить воркеры, иначе они останутся ждать читателя.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results, err := scanner.Scan(ctx, cfg.Hosts, cfg.Ports)
	if err != nil {
		return err
	}
	var checked, opened, failed int
	for result := range results {
		checked++
		if result.State == portscan.StateOpen {
			opened++
		}
		if result.State == portscan.StateError {
			failed++
		}
		if cfg.All || cfg.JSON || result.State == portscan.StateOpen {
			if err := writeResult(output, result, cfg.JSON); err != nil {
				return fmt.Errorf("не удалось записать результат: %w", err)
			}
		} else if result.State == portscan.StateError {
			if _, err := fmt.Fprintf(diagnostics, "%s:%d: %v\n", result.Host, result.Port, result.Err); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(diagnostics, "Проверено: %d, открыто: %d, ошибок: %d\n", checked, opened, failed); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if failed > 0 {
		return errors.New("часть портов не удалось проверить")
	}
	return nil
}
