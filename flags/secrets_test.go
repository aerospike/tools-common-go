package flags

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/config"
	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/aerospike/tools-common-go/secretagent/secretagenttest"
)

const (
	resolvedUser     = "svc-admin"
	resolvedPassword = "hunter2"
	resolvedKeyPass  = "key-pass"
	resolvedCA       = "ca-pem"
	unreachableAgent = "127.0.0.1:1"
)

func encode(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func newTestAgent(t *testing.T) *secretagenttest.Server {
	t.Helper()

	return secretagenttest.NewServer(t, secretagenttest.Secrets{
		"aql": {
			"user":     encode(resolvedUser),
			"password": encode(resolvedPassword),
			"keypass":  encode(resolvedKeyPass),
			"ca":       encode(resolvedCA),
			"envlike":  encode("env:HOME"),
		},
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	return string(data)
}

// parseToolFlags parses args with the Aerospike and Secret Agent flag sets
// combined, as a tool's command does.
func parseToolFlags(t *testing.T, args ...string) (*AerospikeFlags, *SecretAgentFlags) {
	t.Helper()

	af := NewDefaultAerospikeFlags()
	sa := NewDefaultSecretAgentFlags()

	fs := af.NewFlagSet(DefaultWrapHelpString)
	fs.AddFlagSet(sa.NewFlagSet(DefaultWrapHelpString))
	require.NoError(t, fs.Parse(args))

	return af, sa
}

func TestResolveSecrets(t *testing.T) {
	t.Parallel()

	agent := newTestAgent(t)

	af, sa := parseToolFlags(t,
		"-U", "secrets:aql:user", "-P", "secrets:aql:password",
		"--tls-keyfile", "file:"+testFileDataPath, "--tls-keyfile-password", "secrets:aql:keypass",
		"--sa-address", agent.Addr(),
	)

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedUser, af.User)
	require.Equal(t, resolvedPassword, string(af.Password))
	require.Equal(t, resolvedKeyPass, string(af.TLSKeyFilePass))
}

func TestResolveSecretsTLSFiles(t *testing.T) {
	t.Parallel()

	pki, err := secretagenttest.GeneratePKI(t.TempDir())
	require.NoError(t, err)

	ca, cert, key := readFile(t, pki.CAFile), readFile(t, pki.ClientCertFile), readFile(t, pki.ClientKeyFile)

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{
		"tls": {"ca": encode(ca), "cert": encode(cert), "key": encode(key), "keypass": encode(resolvedKeyPass)},
	})

	af, sa := parseToolFlags(t,
		"--tls-enable", "--tls-cafile", "secrets:tls:ca", "--tls-certfile", "secrets:tls:cert",
		"--tls-keyfile", "secrets:tls:key", "--tls-keyfile-password", "secrets:tls:keypass",
		"--sa-address", agent.Addr(),
	)

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, ca, string(af.TLSRootCAFile))
	require.Equal(t, cert, string(af.TLSCertFile))
	require.Equal(t, key, string(af.TLSKeyFile))
	require.Equal(t, resolvedKeyPass, string(af.TLSKeyFilePass))

	tlsConfig, err := af.NewAerospikeConfig().TLS.NewGoTLSConfig()
	require.NoError(t, err)
	require.Len(t, tlsConfig.Certificates, 1)

	_, err = tlsConfig.Certificates[0].Leaf.Verify(x509.VerifyOptions{
		Roots:     tlsConfig.RootCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)
}

func TestResolveSecretsFromConfigFile(t *testing.T) {
	agent := newTestAgent(t)

	file := filepath.Join(t.TempDir(), "astools.conf")
	conf := fmt.Sprintf("[cluster]\nuser = %q\npassword = %q\ntls-cafile = %q\n\n[secret-agent]\nsa-address = %q\n",
		"secrets:aql:user", "secrets:aql:password", "secrets:aql:ca", agent.Addr())
	require.NoError(t, os.WriteFile(file, []byte(conf), 0o600))

	config.Reset()
	t.Cleanup(config.Reset)

	af := NewDefaultAerospikeFlags()
	sa := NewDefaultSecretAgentFlags()

	fs := af.NewFlagSet(DefaultWrapHelpString)
	config.BindPFlags(fs, "cluster")

	saFlags := sa.NewFlagSet(DefaultWrapHelpString)
	config.BindPFlagsWithInstanceFallback(saFlags, "secret-agent")
	fs.AddFlagSet(saFlags)

	require.NoError(t, fs.Parse(nil))

	_, err := config.InitConfig(file, "", fs)
	require.NoError(t, err)

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedUser, af.User)
	require.Equal(t, resolvedPassword, string(af.Password))
	require.Equal(t, resolvedCA, string(af.TLSRootCAFile))
}

func TestResolveSecretsOptionOrder(t *testing.T) {
	t.Parallel()

	agent := newTestAgent(t)

	af, sa := parseToolFlags(t, "-P", "secrets:aql:password", "--sa-address", agent.Addr(), "-U", "admin")
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedPassword, string(af.Password))
}

func TestResolveSecretsUsesValueAsIs(t *testing.T) {
	t.Parallel()

	agent := newTestAgent(t)

	af, sa := parseToolFlags(t, "-U", "admin", "-P", "secrets:aql:envlike", "--sa-address", agent.Addr())
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, "env:HOME", string(af.Password))
}

func TestResolveSecretsTLS(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"password": encode(resolvedPassword)}})

	af, sa := parseToolFlags(t,
		"-U", "admin", "-P", "secrets:aql:password", "--sa-address", agent.Addr(), "--sa-ca-file", agent.CAFile(),
	)
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedPassword, string(af.Password))
}

func TestResolveSecretsSkipsAgent(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"literal password":            {"-U", "admin", "-P", "admin"},
		"secret password, no user":    {"-P", "secrets:aql:password"},
		"secret key pass, no keyfile": {"--tls-keyfile-password", "secrets:aql:keypass"},
		"no password":                 {"-U", "admin"},
		"literal cert files": {
			"--tls-cafile", testFileDataPath, "--tls-certfile", testFileDataPath, "--tls-keyfile", testFileDataPath,
		},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, append(args, "--sa-address", unreachableAgent)...)
			before := string(af.Password)

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, before, string(af.Password))
		})
	}
}

func TestResolveSecretsErrors(t *testing.T) {
	t.Parallel()

	agent := newTestAgent(t)

	tests := map[string]struct {
		class error
		want  []string
		args  []string
	}{
		"missing key": {
			args:  []string{"-U", "admin", "-P", "secrets:aql:missing", "--sa-address", agent.Addr()},
			want:  []string{"--password: ", "secrets:aql:missing"},
			class: secretagent.ErrRequestFailed,
		},
		"user": {
			args:  []string{"-U", "secrets:aql:missing", "-P", "secrets:aql:password", "--sa-address", agent.Addr()},
			want:  []string{"--user: ", "secrets:aql:missing"},
			class: secretagent.ErrRequestFailed,
		},
		"cert file": {
			args:  []string{"--tls-cafile", "secrets:aql:missing", "--sa-address", agent.Addr()},
			want:  []string{"--tls-cafile: ", "secrets:aql:missing"},
			class: secretagent.ErrRequestFailed,
		},
		"key file password": {
			args: []string{
				"--tls-keyfile", "file:" + testFileDataPath, "--tls-keyfile-password", "secrets:aql:missing",
				"--sa-address", agent.Addr(),
			},
			want:  []string{"--tls-keyfile-password: ", "secrets:aql:missing"},
			class: secretagent.ErrRequestFailed,
		},
		"agent down": {
			args:  []string{"-U", "admin", "-P", "secrets:aql:password", "--sa-address", unreachableAgent},
			want:  []string{"--password: ", "secrets:aql:password", unreachableAgent},
			class: secretagent.ErrRequestFailed,
		},
		"bad reference": {
			args:  []string{"-U", "admin", "-P", "secrets:aql:", "--sa-address", agent.Addr()},
			want:  []string{"--password: "},
			class: secretagent.ErrInvalidConfig,
		},
		"bad CA file": {
			args: []string{
				"-U", "admin", "-P", "secrets:aql:password", "--sa-address", agent.Addr(), "--sa-ca-file", "/missing.pem",
			},
			want:  []string{"--sa-ca-file: "},
			class: secretagent.ErrInvalidConfig,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, tt.args...)
			err := af.ResolveSecrets(t.Context(), sa)
			require.ErrorIs(t, err, tt.class)

			for _, want := range tt.want {
				require.ErrorContains(t, err, want)
			}

			require.NotContains(t, err.Error(), resolvedPassword)
		})
	}
}

func TestResolveSecretsInvalidAgentFlags(t *testing.T) {
	t.Parallel()

	af, sa := parseToolFlags(t, "-U", "admin", "-P", "admin", "--sa-port", "0")
	require.ErrorContains(t, af.ResolveSecrets(t.Context(), sa), "--sa-port: invalid value 0")
}

func TestPasswordFlagTypeListsSources(t *testing.T) {
	t.Parallel()

	var flag PasswordFlag

	for _, source := range []string{"env:", "env-b64:", "b64:", "file:", "secrets:"} {
		require.True(t, strings.Contains(flag.Type(), source), source)
	}
}

func TestCertFlagTypeListsSecrets(t *testing.T) {
	t.Parallel()

	var flag CertFlag

	require.Contains(t, flag.Type(), "secrets:<resource>:<key>")
}
