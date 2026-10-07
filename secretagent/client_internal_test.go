package secretagent

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClientDefaults(t *testing.T) {
	t.Parallel()

	c, err := NewClient(Config{})
	require.NoError(t, err)
	require.Equal(t, ConnectionTypeTCP, c.connectionType)
	require.Equal(t, "127.0.0.1:3005", c.address)
	require.Equal(t, DefaultTimeout, c.timeout)
	require.Nil(t, c.tlsConfig)
	require.False(t, c.base64)
}

func TestNewClientCopiesTLSConfig(t *testing.T) {
	t.Parallel()

	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "agent"}

	c, err := NewClient(Config{TLS: cfg})
	require.NoError(t, err)

	cfg.ServerName = "changed"

	require.Equal(t, "agent", c.tlsConfig.ServerName)
}
