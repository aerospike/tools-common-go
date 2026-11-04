package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var tlsFileFlagNames = []string{"tls-cafile", "tls-certfile", "tls-keyfile", "tls-capath"}

func resolveLoaded(t *testing.T, conf string, args ...string) (*AerospikeFlags, error) {
	t.Helper()

	af, sa, err := loadToolConfig(t, conf, "", args...)
	if err != nil {
		return af, err
	}

	err = af.ResolveSecrets(t.Context(), sa)

	return af, err
}

func TestTLSFilesNotReadWithoutTLS(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	for _, name := range tlsFileFlagNames {
		t.Run(name+" on the command line", func(t *testing.T) {
			af, err := resolveLoaded(t, "", "--"+name, missing)
			require.NoError(t, err)
			require.Nil(t, af.NewAerospikeConfig().TLS)
		})

		t.Run(name+" in the config file", func(t *testing.T) {
			af, err := resolveLoaded(t, fmt.Sprintf("[cluster]\n%s = %q\n", name, missing))
			require.NoError(t, err)
			require.Nil(t, af.NewAerospikeConfig().TLS)
		})
	}

	t.Run("tls-cafile from an unset env-b64: variable", func(t *testing.T) {
		_, err := resolveLoaded(t, "", "--tls-cafile", "env-b64:TCG_TEST_UNSET_CA")
		require.NoError(t, err)
	})
}

func TestTLSFilesReadWithTLS(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	for _, name := range tlsFileFlagNames {
		t.Run(name+" on the command line", func(t *testing.T) {
			_, err := resolveLoaded(t, "", "--tls-enable", "--"+name, missing)
			require.ErrorContains(t, err, name)
			require.ErrorContains(t, err, missing)
		})

		t.Run(name+" in the config file", func(t *testing.T) {
			_, err := resolveLoaded(t, fmt.Sprintf("[cluster]\ntls-enable = true\n%s = %q\n", name, missing))
			require.ErrorContains(t, err, name)
			require.ErrorContains(t, err, missing)
		})
	}

	t.Run("a key that fails to decode is not printed", func(t *testing.T) {
		const key = "b64:-----BEGIN PRIVATE KEY-----KeyUniq-5521"

		_, err := resolveLoaded(t, "", "--tls-enable", "--tls-keyfile", key)
		require.ErrorContains(t, err, "tls-keyfile")
		require.NotContains(t, err.Error(), "KeyUniq-5521")
	})

	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(cert, []byte("cert\n"), 0o600))

	caDir := filepath.Join(dir, "ca")
	require.NoError(t, os.Mkdir(caDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(caDir, "a.pem"), []byte("ca-a\n"), 0o600))

	t.Run("files are loaded", func(t *testing.T) {
		af, err := resolveLoaded(t, fmt.Sprintf("[cluster]\ntls-enable = true\ntls-keyfile = %q\n", cert),
			"--tls-cafile", cert, "--tls-certfile", cert, "--tls-capath", caDir)
		require.NoError(t, err)

		tlsConfig := af.NewAerospikeConfig().TLS
		require.NotNil(t, tlsConfig)
		require.Equal(t, [][]byte{[]byte("cert"), []byte("ca-a")}, tlsConfig.RootCA)
		require.Equal(t, []byte("cert"), tlsConfig.Cert)
		require.Equal(t, []byte("cert"), tlsConfig.Key)
	})
}
