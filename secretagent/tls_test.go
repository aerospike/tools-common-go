package secretagent_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/aerospike/tools-common-go/secretagent/secretagenttest"
)

func TestNewTLSConfig(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewMutualTLSServer(t, nil)

	notPEM := filepath.Join(t.TempDir(), "not.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))

	missing := filepath.Join(t.TempDir(), "missing.pem")

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()

		cfg, err := secretagent.NewTLSConfig(secretagent.TLSOptions{})
		require.NoError(t, err)
		require.Nil(t, cfg)
	})

	t.Run("CA only", func(t *testing.T) {
		t.Parallel()

		cfg, err := secretagent.NewTLSConfig(secretagent.TLSOptions{CAFile: agent.CAFile(), ServerName: serverName})
		require.NoError(t, err)
		require.NotNil(t, cfg.RootCAs)
		require.Empty(t, cfg.Certificates)
		require.Equal(t, serverName, cfg.ServerName)
		require.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	})

	t.Run("mutual", func(t *testing.T) {
		t.Parallel()

		cfg, err := secretagent.NewTLSConfig(secretagent.TLSOptions{
			CAFile:     agent.CAFile(),
			CertFile:   agent.ClientCertFile(),
			KeyFile:    agent.ClientKeyFile(),
			MinVersion: tls.VersionTLS13,
		})
		require.NoError(t, err)
		require.Len(t, cfg.Certificates, 1)
		require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	})

	invalid := map[string]secretagent.TLSOptions{
		"missing CA file":        {CAFile: missing},
		"CA file without certs":  {CAFile: notPEM},
		"cert without key":       {CAFile: agent.CAFile(), CertFile: agent.ClientCertFile()},
		"key without cert":       {CAFile: agent.CAFile(), KeyFile: agent.ClientKeyFile()},
		"client cert without CA": {CertFile: agent.ClientCertFile(), KeyFile: agent.ClientKeyFile()},
		"unreadable client cert": {CAFile: agent.CAFile(), CertFile: missing, KeyFile: agent.ClientKeyFile()},
		"mismatched key pair":    {CAFile: agent.CAFile(), CertFile: agent.ClientCertFile(), KeyFile: notPEM},
	}

	for name, opts := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := secretagent.NewTLSConfig(opts)
			requireClass(t, err, secretagent.ErrInvalidConfig)
			require.Nil(t, cfg)
		})
	}
}
