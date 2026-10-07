package secretagent_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/aerospike/tools-common-go/secretagent/internal/wire"
	"github.com/aerospike/tools-common-go/secretagent/secretagenttest"
)

const (
	testSecret   = "hunter2"
	testResource = "res"
	testKey      = "key"
	testRef      = "secrets:res:key"
	bareSecret   = "no-resource"
	literal      = "plain"
	serverName   = "localhost"
	passwordKey  = "password"

	// testTimeout is generous so slow, race-instrumented CI runners do not flake.
	testTimeout = 10 * time.Second
	// unreachableAddr is never listened on: tests only bind ephemeral ports.
	unreachableAddr = "127.0.0.1:1"
)

var sentinels = []error{
	secretagent.ErrInvalidConfig,
	secretagent.ErrUnsupported,
	secretagent.ErrRequestFailed,
	secretagent.ErrInvalidResponse,
}

func requireClass(t *testing.T, err, want error) {
	t.Helper()

	require.ErrorIs(t, err, want)

	for _, other := range sentinels {
		if other != want {
			require.NotErrorIs(t, err, other)
		}
	}
}

func newClient(t *testing.T, cfg secretagent.Config) *secretagent.Client {
	t.Helper()

	client, err := secretagent.NewClient(cfg)
	require.NoError(t, err)

	return client
}

func agentConfig(agent *secretagenttest.Server) secretagent.Config {
	return secretagent.Config{ConnectionType: agent.Network(), Address: agent.Addr(), Timeout: testTimeout}
}

// rawAgent serves every connection with handle, for responses a real agent
// would never send.
func rawAgent(t *testing.T, handle func(net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			wg.Add(1)

			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()

				handle(conn)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()

		wg.Wait()
	})

	return ln.Addr().String()
}

func TestNewClientInvalid(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	tests := map[string]struct {
		cfg  secretagent.Config
		want error
	}{
		"unknown connection type": {
			cfg:  secretagent.Config{ConnectionType: "udp", Address: "127.0.0.1:3005"},
			want: secretagent.ErrInvalidConfig,
		},
		"unix without path": {
			cfg:  secretagent.Config{ConnectionType: secretagent.ConnectionTypeUDS},
			want: secretagent.ErrInvalidConfig,
		},
		"negative timeout": {
			cfg:  secretagent.Config{Timeout: -time.Second},
			want: secretagent.ErrInvalidConfig,
		},
		"TLS over unix": {
			cfg: secretagent.Config{
				ConnectionType: secretagent.ConnectionTypeUDS,
				Address:        "/tmp/agent.sock",
				TLS:            tlsConfig,
			},
			want: secretagent.ErrUnsupported,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client, err := secretagent.NewClient(tt.cfg)
			requireClass(t, err, tt.want)
			require.Nil(t, client)
		})
	}
}

func TestGetSecret(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{
		testResource: {testKey: testSecret},
		"":           {"bare": bareSecret},
	})
	client := newClient(t, agentConfig(agent))

	got, err := client.GetSecret(t.Context(), testResource, testKey)
	require.NoError(t, err)
	require.Equal(t, testSecret, got)

	got, err = client.GetSecret(t.Context(), "", "bare")
	require.NoError(t, err)
	require.Equal(t, bareSecret, got)

	_, err = client.GetSecret(t.Context(), testResource, "missing")
	requireClass(t, err, secretagent.ErrRequestFailed)
	require.ErrorContains(t, err, "secrets:res:missing")

	_, err = client.GetSecret(t.Context(), testResource, "")
	requireClass(t, err, secretagent.ErrInvalidConfig)
}

func TestResolve(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{
		testResource: {testKey: testSecret, "env": "env:NOT_EXPANDED"},
		"":           {"bare": bareSecret},
	})
	client := newClient(t, agentConfig(agent))

	tests := []struct{ value, want string }{
		{value: literal, want: literal},
		{value: "", want: ""},
		{value: "env:HOME", want: "env:HOME"},
		{value: "file:/etc/hosts", want: "file:/etc/hosts"},
		{value: testRef, want: testSecret},
		{value: "secrets:bare", want: bareSecret},
		{value: "secrets:res:env", want: "env:NOT_EXPANDED"},
	}

	for _, tt := range tests {
		got, err := client.Resolve(t.Context(), tt.value)
		require.NoError(t, err, tt.value)
		require.Equal(t, tt.want, got, tt.value)
	}

	_, err := client.Resolve(t.Context(), "secrets:res:")
	requireClass(t, err, secretagent.ErrInvalidConfig)

	_, err = client.Resolve(t.Context(), "secrets:res:missing")
	requireClass(t, err, secretagent.ErrRequestFailed)
}

func TestResolveLiteralSkipsAgent(t *testing.T) {
	t.Parallel()

	client := newClient(t, secretagent.Config{Address: unreachableAddr})

	got, err := client.Resolve(t.Context(), literal)
	require.NoError(t, err)
	require.Equal(t, literal, got)
}

func TestBase64(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{
		testResource: {
			"padded":     "aHVudGVyMg==",
			"newline":    "aHVudGVyMg==\n",
			"whitespace": " \t\r\n",
			"invalid":    testSecret,
		},
	})

	cfg := agentConfig(agent)
	cfg.Base64 = true
	client := newClient(t, cfg)

	for _, key := range []string{"padded", "newline"} {
		got, err := client.GetSecret(t.Context(), testResource, key)
		require.NoError(t, err, key)
		require.Equal(t, testSecret, got, key)
	}

	for _, key := range []string{"whitespace", "invalid"} {
		_, err := client.GetSecret(t.Context(), testResource, key)
		requireClass(t, err, secretagent.ErrInvalidResponse)
		require.NotContains(t, err.Error(), testSecret)
	}

	raw := newClient(t, agentConfig(agent))

	got, err := raw.GetSecret(t.Context(), testResource, "newline")
	require.NoError(t, err)
	require.Equal(t, "aHVudGVyMg==\n", got)
}

func TestEmptySecret(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{testResource: {"empty": ""}})
	client := newClient(t, agentConfig(agent))

	_, err := client.GetSecret(t.Context(), testResource, "empty")
	requireClass(t, err, secretagent.ErrInvalidResponse)
}

func TestUnixSocket(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewUnixServer(t, secretagenttest.Secrets{testResource: {testKey: testSecret}})
	client := newClient(t, agentConfig(agent))

	got, err := client.Resolve(t.Context(), testRef)
	require.NoError(t, err)
	require.Equal(t, testSecret, got)
}

func TestTLS(t *testing.T) {
	t.Parallel()

	secrets := secretagenttest.Secrets{testResource: {testKey: testSecret}}
	server := secretagenttest.NewTLSServer(t, secrets)
	mutual := secretagenttest.NewMutualTLSServer(t, secrets)

	tests := map[string]struct {
		agent *secretagenttest.Server
		opts  secretagent.TLSOptions
		ok    bool
	}{
		"CA": {
			agent: server,
			opts:  secretagent.TLSOptions{CAFile: server.CAFile()},
			ok:    true,
		},
		"server name": {
			agent: server,
			opts:  secretagent.TLSOptions{CAFile: server.CAFile(), ServerName: serverName},
			ok:    true,
		},
		"wrong server name": {
			agent: server,
			opts:  secretagent.TLSOptions{CAFile: server.CAFile(), ServerName: "agent.example.com"},
		},
		"untrusted CA": {
			agent: server,
			opts:  secretagent.TLSOptions{CAFile: mutual.CAFile()},
		},
		"mutual": {
			agent: mutual,
			opts: secretagent.TLSOptions{
				CAFile:   mutual.CAFile(),
				CertFile: mutual.ClientCertFile(),
				KeyFile:  mutual.ClientKeyFile(),
			},
			ok: true,
		},
		"mutual without client cert": {
			agent: mutual,
			opts:  secretagent.TLSOptions{CAFile: mutual.CAFile()},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tlsConfig, err := secretagent.NewTLSConfig(tt.opts)
			require.NoError(t, err)

			cfg := agentConfig(tt.agent)
			cfg.TLS = tlsConfig
			client := newClient(t, cfg)

			got, err := client.GetSecret(t.Context(), testResource, testKey)
			if !tt.ok {
				requireClass(t, err, secretagent.ErrRequestFailed)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testSecret, got)
		})
	}
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	addr := rawAgent(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
	client := newClient(t, secretagent.Config{Address: addr, Timeout: 100 * time.Millisecond})

	start := time.Now()
	_, err := client.GetSecret(t.Context(), testResource, testKey)

	requireClass(t, err, secretagent.ErrRequestFailed)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestCancel(t *testing.T) {
	t.Parallel()

	addr := rawAgent(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
	client := newClient(t, secretagent.Config{Address: addr, Timeout: time.Minute})

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := client.GetSecret(ctx, testResource, testKey)

	requireClass(t, err, secretagent.ErrRequestFailed)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestUnreachable(t *testing.T) {
	t.Parallel()

	tests := map[string]secretagent.Config{
		"tcp":  {Address: unreachableAddr, Timeout: testTimeout},
		"unix": {ConnectionType: secretagent.ConnectionTypeUDS, Address: filepath.Join(t.TempDir(), "none.sock")},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := newClient(t, cfg).GetSecret(t.Context(), testResource, testKey)
			requireClass(t, err, secretagent.ErrRequestFailed)
			require.ErrorContains(t, err, cfg.Address)
		})
	}
}

func TestInvalidResponse(t *testing.T) {
	t.Parallel()

	frame := func(magic uint32, body string) []byte {
		msg := make([]byte, wire.HeaderSize, wire.HeaderSize+len(body))
		binary.BigEndian.PutUint32(msg[:4], magic)
		binary.BigEndian.PutUint32(msg[4:], uint32(len(body))) //nolint:gosec // test bodies are tiny

		return append(msg, body...)
	}

	tests := map[string]struct {
		response []byte
		want     error
	}{
		"invalid magic": {
			response: frame(0xdeadbeef, "{}"),
			want:     secretagent.ErrInvalidResponse,
		},
		"malformed body": {
			response: frame(wire.Magic, `{"SecretValue":"`+testSecret),
			want:     secretagent.ErrInvalidResponse,
		},
		"truncated body": {
			response: frame(wire.Magic, `{"SecretValue":"`+testSecret+`"}`)[:wire.HeaderSize+4],
			want:     secretagent.ErrRequestFailed,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addr := rawAgent(t, func(conn net.Conn) {
				var req wire.Request
				if wire.Read(conn, &req) == nil {
					_, _ = conn.Write(tt.response)
				}
			})
			client := newClient(t, secretagent.Config{Address: addr, Timeout: testTimeout})

			_, err := client.GetSecret(t.Context(), testResource, testKey)
			requireClass(t, err, tt.want)
			require.NotContains(t, err.Error(), testSecret)
		})
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{testResource: {testKey: testSecret}})
	client := newClient(t, agentConfig(agent))

	var wg sync.WaitGroup

	errs := make(chan error, 32)

	for range cap(errs) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			got, err := client.GetSecret(t.Context(), testResource, testKey)
			if err == nil && got != testSecret {
				err = errors.New("unexpected secret value")
			}

			errs <- err
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}
