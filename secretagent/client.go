// Package secretagent is a client for the Aerospike Secret Agent. It resolves
// secrets:[<resource>:]<key> references the same way the Aerospike C tools do.
package secretagent

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aerospike/tools-common-go/secretagent/internal/wire"
)

const (
	ConnectionTypeTCP = "tcp"
	ConnectionTypeUDS = "unix"

	DefaultHost    = "127.0.0.1"
	DefaultPort    = 3005
	DefaultTimeout = time.Second
)

const trailingWhitespace = " \t\n\r\f\v"

var aLongTimeAgo = time.Unix(1, 0)

// Config configures a Client. The zero value connects over TCP to
// DefaultHost:DefaultPort without TLS.
type Config struct {
	// TLS enables TLS when set. It is only valid with ConnectionTypeTCP.
	// See NewTLSConfig.
	TLS *tls.Config
	// ConnectionType is ConnectionTypeTCP (default) or ConnectionTypeUDS.
	ConnectionType string
	// Address is host:port for TCP or a socket path for UDS. It defaults to
	// DefaultHost:DefaultPort for TCP and is required for UDS.
	Address string
	// Timeout bounds each request, from dial to response. Zero means
	// DefaultTimeout.
	Timeout time.Duration
	// Base64 decodes secret values, as the Aerospike C tools always do.
	Base64 bool
}

// Client fetches secrets from an Aerospike Secret Agent. It opens one
// connection per request and is safe for concurrent use.
type Client struct {
	tlsConfig      *tls.Config
	connectionType string
	address        string
	timeout        time.Duration
	base64         bool
}

// NewClient validates cfg and returns a Client. It does not contact the agent.
func NewClient(cfg Config) (*Client, error) {
	c := &Client{
		tlsConfig:      cfg.TLS.Clone(),
		connectionType: cfg.ConnectionType,
		address:        cfg.Address,
		timeout:        cfg.Timeout,
		base64:         cfg.Base64,
	}

	if c.connectionType == "" {
		c.connectionType = ConnectionTypeTCP
	}

	switch c.connectionType {
	case ConnectionTypeTCP:
		if c.address == "" {
			c.address = net.JoinHostPort(DefaultHost, strconv.Itoa(DefaultPort))
		}
	case ConnectionTypeUDS:
		if c.tlsConfig != nil {
			return nil, fmt.Errorf("%w: TLS over a unix socket", ErrUnsupported)
		}

		if c.address == "" {
			return nil, fmt.Errorf("%w: unix socket path is required", ErrInvalidConfig)
		}
	default:
		return nil, fmt.Errorf("%w: unknown connection type %q, use %q or %q",
			ErrInvalidConfig, c.connectionType, ConnectionTypeTCP, ConnectionTypeUDS)
	}

	switch {
	case c.timeout < 0:
		return nil, fmt.Errorf("%w: negative timeout %s", ErrInvalidConfig, c.timeout)
	case c.timeout == 0:
		c.timeout = DefaultTimeout
	}

	return c, nil
}

// GetSecret fetches the value of key in resource. An empty resource is left out
// of the request, as with a secrets:<key> reference.
func (c *Client) GetSecret(ctx context.Context, resource, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("%w: empty secret key", ErrInvalidConfig)
	}

	return c.get(ctx, Ref{Resource: resource, Key: key})
}

// Resolve returns value unchanged when it is not a secret reference, and the
// fetched secret otherwise. The secret is returned as is and must not be parsed
// again, for example as an env: or file: value.
func (c *Client) Resolve(ctx context.Context, value string) (string, error) {
	if !IsSecret(value) {
		return value, nil
	}

	ref, err := ParseRef(value)
	if err != nil {
		return "", err
	}

	return c.get(ctx, ref)
}

func (c *Client) get(ctx context.Context, ref Ref) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: connect to %s over %s for %s: %w",
			ErrRequestFailed, c.address, c.connectionType, ref, err)
	}

	defer func() { _ = conn.Close() }()

	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(aLongTimeAgo) })
	defer stop()

	value, err := exchange(conn, ref)
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, ErrRequestFailed) {
			return "", fmt.Errorf("%w: %s: %w", ErrRequestFailed, ref, context.Cause(ctx))
		}

		return "", err
	}

	return c.decode(ref, value)
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.tlsConfig != nil {
		d := tls.Dialer{Config: c.tlsConfig}

		return d.DialContext(ctx, c.connectionType, c.address)
	}

	var d net.Dialer

	return d.DialContext(ctx, c.connectionType, c.address)
}

func exchange(conn net.Conn, ref Ref) (string, error) {
	err := wire.Write(conn, wire.Request{Resource: ref.Resource, SecretKey: ref.Key})
	if err != nil {
		if errors.Is(err, wire.ErrTooLarge) {
			return "", fmt.Errorf("%w: request for %s: %w", ErrInvalidConfig, ref, err)
		}

		return "", fmt.Errorf("%w: send request for %s: %w", ErrRequestFailed, ref, err)
	}

	var res wire.Response

	if err = wire.Read(conn, &res); err != nil {
		if errors.Is(err, wire.ErrProtocol) {
			return "", fmt.Errorf("%w: response for %s: %w", ErrInvalidResponse, ref, err)
		}

		return "", fmt.Errorf("%w: read response for %s: %w", ErrRequestFailed, ref, err)
	}

	if res.Error != "" {
		return "", fmt.Errorf("%w: agent error for %s: %s", ErrRequestFailed, ref, res.Error)
	}

	if res.SecretValue == "" {
		return "", fmt.Errorf("%w: empty secret for %s", ErrInvalidResponse, ref)
	}

	return res.SecretValue, nil
}

func (c *Client) decode(ref Ref, value string) (string, error) {
	if !c.base64 {
		return value, nil
	}

	encoded := strings.TrimRight(value, trailingWhitespace)
	if encoded == "" {
		return "", fmt.Errorf("%w: whitespace-only secret for %s", ErrInvalidResponse, ref)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: secret for %s is not valid base64: %w", ErrInvalidResponse, ref, err)
	}

	return string(decoded), nil
}
