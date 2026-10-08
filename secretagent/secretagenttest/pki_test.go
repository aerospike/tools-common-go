package secretagenttest_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/secretagent/secretagenttest"
)

func TestGeneratePKI(t *testing.T) {
	t.Parallel()

	pki, err := secretagenttest.GeneratePKI(t.TempDir())
	require.NoError(t, err)

	caPEM, err := os.ReadFile(pki.CAFile)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))

	server, err := tls.LoadX509KeyPair(pki.ServerCertFile, pki.ServerKeyFile)
	require.NoError(t, err)

	for _, host := range []string{"127.0.0.1", "localhost"} {
		_, err = server.Leaf.Verify(x509.VerifyOptions{
			Roots:     roots,
			DNSName:   host,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(t, err, host)
	}

	client, err := tls.LoadX509KeyPair(pki.ClientCertFile, pki.ClientKeyFile)
	require.NoError(t, err)

	_, err = client.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)

	_, err = client.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.Error(t, err, "the client certificate must not be usable as a server certificate")

	for _, keyFile := range []string{pki.ServerKeyFile, pki.ClientKeyFile} {
		info, statErr := os.Stat(keyFile)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), keyFile)
	}
}

func TestGeneratePKIMissingDirectory(t *testing.T) {
	t.Parallel()

	pki, err := secretagenttest.GeneratePKI(filepath.Join(t.TempDir(), "missing"))
	require.ErrorContains(t, err, "secretagenttest: write ca.pem")
	require.Equal(t, secretagenttest.PKI{}, pki)
}
