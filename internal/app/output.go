package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"portscanner/pkg/portscan"
)

// resultOutput - формат одной строки JSON. Ошибка передаётся текстом.
type resultOutput struct {
	Host     string         `json:"host"`
	IP       string         `json:"ip,omitempty"`
	Port     uint16         `json:"port"`
	State    portscan.State `json:"state"`
	Duration string         `json:"duration"`
	Error    string         `json:"error,omitempty"`
}

func writeResult(output io.Writer, result portscan.Result, asJSON bool) error {
	row := resultOutput{
		Host: result.Host, Port: result.Port, State: result.State,
		Duration: result.Duration.Round(time.Microsecond).String(),
	}
	if result.IP != nil {
		row.IP = result.IP.String()
	}
	if result.Err != nil {
		row.Error = result.Err.Error()
	}
	if asJSON {
		return json.NewEncoder(output).Encode(row)
	}
	host := row.IP
	if host == "" {
		host = row.Host
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(row.Port)))
	if row.Error != "" {
		_, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\t%s\n", row.Host, address, row.State, row.Duration, row.Error)
		return err
	}
	_, err := fmt.Fprintf(output, "%s\t%s\t%s\t%s\n", row.Host, address, row.State, row.Duration)
	return err
}
