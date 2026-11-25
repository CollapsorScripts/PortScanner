package config

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"portscanner/pkg/portscan"
)

// Config - параметры запуска сканера.
type Config struct {
	Hosts       []string
	Ports       portscan.PortSet
	Concurrency int
	Timeout     time.Duration
	All         bool
	JSON        bool
}

// Load - разбирает аргументы. Список хостов передаётся после флагов.
func Load(args []string, output io.Writer) (Config, error) {
	var cfg Config
	var ports string
	flags := flag.NewFlagSet("portscanner", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&ports, "ports", "22,80,443", "порты и диапазоны через запятую")
	flags.IntVar(&cfg.Concurrency, "workers", 100, "число одновременных подключений")
	flags.DurationVar(&cfg.Timeout, "timeout", 500*time.Millisecond, "таймаут подключения")
	flags.BoolVar(&cfg.All, "all", false, "показывать все состояния портов")
	flags.BoolVar(&cfg.JSON, "json", false, "выводить каждый результат отдельной строкой JSON")
	flags.Usage = func() {
		fmt.Fprintln(output, "Использование: portscanner [флаги] хост [хост ...]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	cfg.Hosts = flags.Args()
	if len(cfg.Hosts) == 0 {
		return Config{}, fmt.Errorf("укажи хотя бы один хост")
	}
	for _, host := range cfg.Hosts {
		if strings.HasPrefix(host, "-") {
			return Config{}, fmt.Errorf("флаги нужно указывать перед хостами: %s", host)
		}
	}
	if cfg.Concurrency < 1 {
		return Config{}, fmt.Errorf("число подключений должно быть больше нуля")
	}
	if cfg.Timeout <= 0 {
		return Config{}, fmt.Errorf("таймаут должен быть больше нуля")
	}
	var err error
	cfg.Ports, err = portscan.ParsePorts(ports)
	if err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать порты: %w", err)
	}
	return cfg, nil
}
