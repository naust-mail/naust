package helper

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
)

// Client invokes intents on a running helperd from the manager side.
// One request per connection, matching the server: dial, send one JSON
// line, read one JSON line back.
type Client struct {
	SocketPath string
}

// Call executes one intent and returns its output. The context bounds
// the whole exchange including execution time on the helper side, so
// long-running intents (apt) need a generous deadline.
func (c *Client) Call(ctx context.Context, intent string, args map[string]string) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return "", fmt.Errorf("helper %s: %w", intent, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	buf, err := json.Marshal(Request{Intent: intent, Args: args})
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(append(buf, '\n')); err != nil {
		return "", fmt.Errorf("helper %s: %w", intent, err)
	}

	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxRequestLine), 64<<10).ReadBytes('\n')
	if err != nil {
		return "", fmt.Errorf("helper %s: %w", intent, err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return "", fmt.Errorf("helper %s: malformed response", intent)
	}
	if !resp.OK {
		return "", errors.New(resp.Error)
	}
	return resp.Result, nil
}
