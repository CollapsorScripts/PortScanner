package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"portscanner/internal/app"
	"portscanner/internal/config"
	"portscanner/pkg/portscan"
)

func main() {
	os.Exit(run())
}

// run - загружает настройки и ждёт завершения сканирования или сигнала остановки.
func run() int {
	cfg, err := config.Load(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), signals...)
	defer stop()
	if err := app.Run(ctx, cfg, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "Сканирование остановлено")
			return 130
		}
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, portscan.ErrInvalidHost) || errors.Is(err, portscan.ErrEmptyHost) {
			return 2
		}
		return 1
	}
	return 0
}
