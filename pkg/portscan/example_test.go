package portscan_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"portscanner/pkg/portscan"
)

func ExampleScanner_Scan() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ports := portscan.Union(portscan.Ports(22, 80, 443), portscan.Range(8000, 8100))
	results, err := scanner.Scan(ctx, []string{"127.0.0.1", "localhost"}, ports)
	if err != nil {
		log.Fatal(err)
	}
	for r := range results {
		if r.State == portscan.StateOpen {
			fmt.Printf("%s (%s):%d open in %s\n", r.Host, r.IP, r.Port, r.Duration)
		}
	}
	if err := ctx.Err(); err != nil {
		log.Printf("scan interrupted: %v", err)
	}
}
