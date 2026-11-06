package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	t.Run("tls-keyfile-password on the command line", func(t *testing.T) {
		af, err := resolveLoaded(t, "", "--tls-keyfile", missing, "--tls-keyfile-password", "file:"+missing)
		require.NoError(t, err)
		require.Empty(t, af.TLSKeyFilePass)
	})

	t.Run("tls-keyfile-password in the config file", func(t *testing.T) {
		conf := fmt.Sprintf("[cluster]\ntls-keyfile = %q\ntls-keyfile-password = \"env:TCG_TEST_UNSET\"\n", missing)

		af, err := resolveLoaded(t, conf)
		require.NoError(t, err)
		require.Empty(t, af.TLSKeyFilePass)
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

	t.Run("labels", func(t *testing.T) {
		_, err := resolveLoaded(t, "", "--tls-enable", "--tls-keyfile", missing)
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "--tls-keyfile: "), err.Error())

		_, err = resolveLoaded(t, fmt.Sprintf("[cluster]\ntls-enable = true\ntls-keyfile = %q\n", missing))
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "tls-keyfile in config file: "), err.Error())
	})

	t.Run("an unset env-b64: variable is named", func(t *testing.T) {
		_, err := resolveLoaded(t, "", "--tls-enable", "--tls-cafile", "env-b64:TCG_TEST_UNSET_CA")
		require.ErrorIs(t, err, ErrEnvironmentVariableNotFound)
		require.EqualError(t, err, "--tls-cafile: environment variable TCG_TEST_UNSET_CA is not set or empty")
	})

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

func TestTLSFilesRetryAfterReadError(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(cert, []byte("cert\n"), 0o600))

	af, sa, err := loadToolConfig(t, "", "",
		"--tls-enable", "--tls-cafile", filepath.Join(dir, "missing"), "--tls-certfile", cert)
	require.NoError(t, err)

	first := af.ResolveSecrets(t.Context(), sa)
	require.ErrorContains(t, first, "--tls-cafile: ")

	require.EqualError(t, af.ResolveSecrets(t.Context(), sa), first.Error())
}

func TestTLSFileGivenTwice(t *testing.T) {
	agent := newTestAgent(t)

	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	ca := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(ca, []byte("ca-file\n"), 0o600))

	tests := map[string]struct {
		agent string
		want  string
		args  []string
	}{
		"path then secrets:": {
			args: []string{"--tls-cafile", missing, "--tls-cafile", "secrets:aql:ca"}, agent: agent.Addr(), want: resolvedCA,
		},
		"secrets: then path": {
			args: []string{"--tls-cafile", "secrets:aql:ca", "--tls-cafile", ca}, agent: unreachableAgent, want: "ca-file",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			af, err := resolveLoaded(t, "", append(tt.args, "--tls-enable", "--sa-address", tt.agent)...)
			require.NoError(t, err)
			require.Equal(t, tt.want, string(af.TLSRootCAFile))
		})
	}
}

func TestTLSFilesCommandLineTLSOffOverConfigFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	conf := fmt.Sprintf("[cluster]\ntls-enable = true\ntls-keyfile = %q\ntls-cafile = %q\n", missing, missing)

	af, err := resolveLoaded(t, conf, "--tls-enable=false")
	require.NoError(t, err)
	require.Nil(t, af.NewAerospikeConfig().TLS)
}

func TestTLSFilesInitConfigFiles(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	keyFile := fmt.Sprintf("tls-keyfile = %q\n", missing)

	resolve := func(t *testing.T, af *AerospikeFlags, sa *SecretAgentFlags, err error) error {
		t.Helper()
		require.NoError(t, err)

		return af.ResolveSecrets(t.Context(), sa)
	}

	t.Run("without TLS", func(t *testing.T) {
		af, sa, err := loadToolConfigFiles(t, "[cluster]\n"+keyFile, "", "")
		require.NoError(t, resolve(t, af, sa, err))
	})

	t.Run("with TLS", func(t *testing.T) {
		af, sa, err := loadToolConfigFiles(t, "[cluster]\ntls-enable = true\n"+keyFile, "", "")
		err = resolve(t, af, sa, err)
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "tls-keyfile in config file: "), err.Error())
	})

	t.Run("instance without TLS", func(t *testing.T) {
		af, sa, err := loadToolConfigFiles(t, "[cluster_x]\n"+keyFile, "", "x")
		require.NoError(t, resolve(t, af, sa, err))
	})

	t.Run("instance with TLS", func(t *testing.T) {
		af, sa, err := loadToolConfigFiles(t, "[cluster_x]\ntls-enable = true\n"+keyFile, "", "x")
		err = resolve(t, af, sa, err)
		require.Error(t, err)
		require.True(t, strings.HasPrefix(err.Error(), "tls-keyfile in config file: "), err.Error())
	})
}
