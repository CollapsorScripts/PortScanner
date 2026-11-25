package config

import (
	"errors"
	"flag"
	"io"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	cfg, err := Load([]string{"-ports", "80,443,80", "-workers", "4", "-timeout", "1s", "-json", "localhost", "::1"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ports.Len() != 2 || cfg.Concurrency != 4 || cfg.Timeout != time.Second || !cfg.JSON || len(cfg.Hosts) != 2 {
		t.Fatalf("неверные параметры: %+v", cfg)
	}
}

func TestLoadErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-ports", "0", "localhost"},
		{"-ports", "100-1", "localhost"},
		{"-workers", "0", "localhost"},
		{"-timeout", "0s", "localhost"},
		{"-timeout", "bad", "localhost"},
		{"localhost", "-all"},
		{"-unknown", "localhost"},
	} {
		if _, err := Load(args, io.Discard); err == nil {
			t.Errorf("ожидалась ошибка для %q", args)
		}
	}
	if _, err := Load([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ожидался запрос справки: %v", err)
	}
}
