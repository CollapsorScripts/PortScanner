package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"portscanner/internal/config"
	"portscanner/pkg/portscan"
)

func TestRunLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	cfg := config.Config{
		Hosts: []string{"127.0.0.1"}, Ports: portscan.Ports(listener.Addr().(*net.TCPAddr).Port),
		Concurrency: 2, Timeout: time.Second, JSON: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var output, diagnostics bytes.Buffer
	if err := Run(ctx, cfg, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(output.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if row["state"] != "open" || row["ip"] != "127.0.0.1" || !strings.Contains(diagnostics.String(), "открыто: 1") {
		t.Fatalf("неверный результат: %s; %s", output.String(), diagnostics.String())
	}
	if err := Run(ctx, cfg, brokenWriter{}, io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("потеряна ошибка записи: %v", err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRunReportsInvalidHost(t *testing.T) {
	cfg := config.Config{
		Hosts: []string{"bad host"}, Ports: portscan.Ports(80), Concurrency: 1, Timeout: time.Second,
	}
	if err := Run(context.Background(), cfg, io.Discard, io.Discard); !errors.Is(err, portscan.ErrInvalidHost) {
		t.Fatalf("ожидалась ошибка хоста: %v", err)
	}
}

func TestWriteResult(t *testing.T) {
	var output bytes.Buffer
	result := portscan.Result{Host: "::1", IP: net.ParseIP("::1"), Port: 80, State: portscan.StateClosed}
	if err := writeResult(&output, result, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[::1]:80\tclosed") {
		t.Fatalf("неверный адрес IPv6: %s", output.String())
	}
	output.Reset()
	result.IP = nil
	result.State = portscan.StateError
	result.Err = portscan.ErrResolve
	if err := writeResult(&output, result, true); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(output.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	if _, exists := row["ip"]; exists || row["error"] != portscan.ErrResolve.Error() {
		t.Fatalf("неверный вывод ошибки: %s", output.String())
	}
}
