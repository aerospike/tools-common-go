package flags

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	literalKeyPass   = "kp-s3cr3t"
	nbsp             = "\u00a0"
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
			"reflike":  encode("secrets:aql:password"),
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

	fs := af.NewFlagSetWithSecrets(DefaultWrapHelpString)
	fs.AddFlagSet(sa.NewFlagSet(DefaultWrapHelpString))
	require.NoError(t, fs.Parse(args))

	return af, sa
}

func TestResolveSecrets(t *testing.T) {
	t.Parallel()

	agent := newTestAgent(t)

	af, sa := parseToolFlags(t,
		"-U", "secrets:aql:user", "-P", "secrets:aql:password", "--tls-enable",
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

// parseToolConfig reads conf as the config file of a tool with no command line
// arguments, with [cluster] and [secret-agent] bound as a tool's command does.
func parseToolConfig(t *testing.T, conf string) (*AerospikeFlags, *SecretAgentFlags) {
	t.Helper()

	return parseToolConfigArgs(t, conf, "")
}

// parseToolConfigArgs is parseToolConfig with an instance and command line
// arguments.
func parseToolConfigArgs(t *testing.T, conf, instance string, args ...string) (*AerospikeFlags, *SecretAgentFlags) {
	t.Helper()

	af, sa, err := loadToolConfig(t, conf, instance, args...)
	require.NoError(t, err)

	return af, sa
}

// loadToolConfig is parseToolConfigArgs returning the command line or config
// file error.
func loadToolConfig(t *testing.T, conf, instance string, args ...string) (*AerospikeFlags, *SecretAgentFlags, error) {
	t.Helper()

	file := filepath.Join(t.TempDir(), "astools.conf")
	require.NoError(t, os.WriteFile(file, []byte(conf), 0o600))

	config.Reset()
	t.Cleanup(config.Reset)

	af := NewDefaultAerospikeFlags()
	sa := NewDefaultSecretAgentFlags()

	fs := af.NewFlagSetWithSecrets(DefaultWrapHelpString)
	config.BindPFlags(fs, "cluster")

	saFlags := sa.NewFlagSet(DefaultWrapHelpString)
	config.BindPFlagsWithInstanceFallback(saFlags, "secret-agent")
	fs.AddFlagSet(saFlags)

	if err := fs.Parse(args); err != nil {
		return af, sa, err
	}

	_, err := config.InitConfig(file, instance, fs)

	return af, sa, err
}

// loadToolConfigFiles is loadToolConfig with config.InitConfigFiles: home is
// the $HOME/.aerospike file and user the --config-file, each written only when
// not empty. A config name of its own keeps a real /etc/aerospike file out.
func loadToolConfigFiles(t *testing.T, home, user, instance string, args ...string) (
	*AerospikeFlags, *SecretAgentFlags, error,
) {
	t.Helper()

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	config.SetDefaultConfName("astools-flags-test")
	t.Cleanup(func() { config.SetDefaultConfName(config.DefaultConfName) })

	if home != "" {
		require.NoError(t, os.Mkdir(filepath.Join(homeDir, ".aerospike"), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(homeDir, ".aerospike", "astools-flags-test.conf"),
			[]byte(home), 0o600))
	}

	userFile := ""
	if user != "" {
		userFile = filepath.Join(t.TempDir(), "user.conf")
		require.NoError(t, os.WriteFile(userFile, []byte(user), 0o600))
	}

	config.Reset()
	t.Cleanup(config.Reset)

	af := NewDefaultAerospikeFlags()
	sa := NewDefaultSecretAgentFlags()

	fs := af.NewFlagSetWithSecrets(DefaultWrapHelpString)
	config.BindPFlags(fs, "cluster")

	saFlags := sa.NewFlagSet(DefaultWrapHelpString)
	config.BindPFlagsWithInstanceFallback(saFlags, "secret-agent")
	fs.AddFlagSet(saFlags)

	if err := fs.Parse(args); err != nil {
		return af, sa, err
	}

	_, err := config.InitConfigFiles(userFile, instance, fs)

	return af, sa, err
}

// resolveToolConfig loads conf and args as a tool does and resolves the
// secrets, returning the first error.
func resolveToolConfig(t *testing.T, conf, instance string, args ...string) error {
	t.Helper()

	af, sa, err := loadToolConfig(t, conf, instance, args...)
	if err != nil {
		return err
	}

	return af.ResolveSecrets(t.Context(), sa)
}

// newProxy forwards connections accepted on listenAddr to backend and counts
// them. It skips the test when listenAddr is IPv6 and the host has no IPv6
// loopback.
func newProxy(t *testing.T, listenAddr, backend string) (string, *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil && strings.HasPrefix(listenAddr, "[") {
		t.Skipf("no IPv6 loopback: %v", err)
	}

	require.NoError(t, err)

	var (
		conns atomic.Int32
		wg    sync.WaitGroup
	)

	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}

			conns.Add(1)
			wg.Add(1)

			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()

				upstream, dialErr := net.Dial("tcp", backend)
				if dialErr != nil {
					return
				}

				go func() {
					_, _ = io.Copy(upstream, conn)
					_ = upstream.Close()
				}()

				_, _ = io.Copy(conn, upstream)
				_ = upstream.Close()
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()

		wg.Wait()
	})

	return ln.Addr().String(), &conns
}

func TestResolveSecretsFromConfigFile(t *testing.T) {
	agent := newTestAgent(t)

	af, sa := parseToolConfig(t, fmt.Sprintf(
		"[cluster]\nuser = %q\npassword = %q\ntls-enable = true\ntls-cafile = %q\n\n[secret-agent]\nsa-address = %q\n",
		"secrets:aql:user", "secrets:aql:password", "secrets:aql:ca", agent.Addr()))

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedUser, af.User)
	require.Equal(t, resolvedPassword, string(af.Password))
	require.Equal(t, resolvedCA, string(af.TLSRootCAFile))
}

func TestResolveSecretsFromConfigFileCSpellingCAFile(t *testing.T) {
	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"password": encode(resolvedPassword)}})

	af, sa := parseToolConfig(t, fmt.Sprintf(
		"[cluster]\nuser = %q\npassword = %q\n\n[secret-agent]\nsa-address = %q\nsa-cafile = %q\n",
		"admin", "secrets:aql:password", agent.Addr(), agent.CAFile()))

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedPassword, string(af.Password))
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

func TestResolveSecretsResolvesOnce(t *testing.T) {
	t.Parallel()

	agent := newTestAgent(t)

	af, sa := parseToolFlags(t, "-U", "admin", "-P", "secrets:aql:reflike", "--sa-address", agent.Addr())
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, "secrets:aql:password", string(af.Password))
}

func TestResolveSecretsExpandedValuesStayLiteral(t *testing.T) {
	const expanded = "secrets:" + resolvedPassword

	t.Setenv("TCG_TEST_SECRET_REF", expanded)
	t.Setenv("TCG_TEST_SECRET_REF_B64", encode(expanded))

	file := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(file, []byte(expanded+"\n"), 0o600))

	password := func(af *AerospikeFlags) string { return string(af.Password) }

	tests := map[string]struct {
		got  func(*AerospikeFlags) string
		args []string
	}{
		"b64":     {args: []string{"-U", "lit", "-P", "b64:" + encode(expanded)}, got: password},
		"env":     {args: []string{"-U", "lit", "-P", "env:TCG_TEST_SECRET_REF"}, got: password},
		"env-b64": {args: []string{"-U", "lit", "-P", "env-b64:TCG_TEST_SECRET_REF_B64"}, got: password},
		"file":    {args: []string{"-U", "lit", "-P", "file:" + file}, got: password},
		"later literal": {
			args: []string{"-U", "lit", "-P", "secrets:aql:password", "-P", "b64:" + encode(expanded)},
			got:  password,
		},
		"key file password": {
			args: []string{"--tls-keyfile", "file:" + testFileDataPath, "--tls-keyfile-password", "b64:" + encode(expanded)},
			got:  func(af *AerospikeFlags) string { return string(af.TLSKeyFilePass) },
		},
		"cert file": {
			args: []string{"--tls-cafile", "b64:" + encode(expanded)},
			got:  func(af *AerospikeFlags) string { return string(af.TLSRootCAFile) },
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolFlags(t, append(tt.args, "--sa-address", unreachableAgent)...)
			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, expanded, tt.got(af))
		})
	}
}

func TestResolveSecretsExpandedConfigValueStaysLiteral(t *testing.T) {
	const expanded = "secrets:" + resolvedPassword

	af, sa := parseToolConfig(t, fmt.Sprintf("[cluster]\nuser = %q\npassword = %q\n\n[secret-agent]\nsa-address = %q\n",
		"lit", "b64:"+encode(expanded), unreachableAgent))

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, expanded, string(af.Password))
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

func TestResolveSecretsNeedsFlagSetWithSecrets(t *testing.T) {
	t.Parallel()

	af := NewDefaultAerospikeFlags()
	require.NoError(t, af.NewFlagSet(DefaultWrapHelpString).Parse([]string{"-U", "admin", "-P", "admin"}))
	require.ErrorIs(t, af.ResolveSecrets(t.Context(), NewDefaultSecretAgentFlags()), errSecretsNotTracked)
}

// Tools that resolve secrets themselves wrap these flag values by type, so
// NewFlagSet must keep the original types.
func TestNewFlagSetKeepsFlagValueTypes(t *testing.T) {
	t.Parallel()

	fs := NewDefaultAerospikeFlags().NewFlagSet(DefaultWrapHelpString)

	for _, name := range []string{"tls-cafile", "tls-certfile", "tls-keyfile"} {
		require.IsType(t, (*CertFlag)(nil), fs.Lookup(name).Value, name)
	}

	for _, name := range []string{"password", "tls-keyfile-password"} {
		require.IsType(t, (*PasswordFlag)(nil), fs.Lookup(name).Value, name)
	}

	require.Error(t, fs.Parse([]string{"--tls-cafile", "secrets:tls:ca"}))
}

func TestResolveSecretsSkipsAgent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		password string
		args     []string
	}{
		"literal password":            {args: []string{"-U", "admin", "-P", "admin"}, password: "admin"},
		"secret password, no user":    {args: []string{"-P", "secrets:aql:password"}},
		"secret password, PKI":        {args: []string{"-U", "admin", "--auth", "pki", "-P", "secrets:aql:password"}},
		"secret key pass, no keyfile": {args: []string{"--tls-keyfile-password", "secrets:aql:keypass"}},
		"no password":                 {args: []string{"-U", "admin"}},
		"literal cert files": {
			args: []string{
				"--tls-cafile", testFileDataPath, "--tls-certfile", testFileDataPath, "--tls-keyfile", testFileDataPath,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, append(tt.args, "--sa-address", unreachableAgent)...)

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, tt.password, string(af.Password))
			require.Empty(t, af.TLSKeyFilePass)
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
			args:  []string{"--tls-enable", "--tls-cafile", "secrets:aql:missing", "--sa-address", agent.Addr()},
			want:  []string{"--tls-cafile: ", "secrets:aql:missing"},
			class: secretagent.ErrRequestFailed,
		},
		"key file password": {
			args: []string{
				"--tls-enable", "--tls-keyfile", "file:" + testFileDataPath,
				"--tls-keyfile-password", "secrets:aql:missing", "--sa-address", agent.Addr(),
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

	tests := map[string]struct {
		want string
		args []string
	}{
		"address": {
			args: []string{"--sa-address", "[localhost]:3005"},
			want: `--sa-address: invalid value "[localhost]:3005", expected <host>[:<port>] or [<ipv6>][:<port>]`,
		},
		"port": {args: []string{"--sa-port", "0"}, want: `--sa-port: invalid value "0", expected an integer from 1 to 65535`},
		"timeout": {
			args: []string{"--sa-timeout", "2147483648"},
			want: `--sa-timeout: invalid value "2147483648", expected an integer from 1 to 2147483647`,
		},
		"CA file": {
			args: []string{"--sa-ca-file", ""},
			want: `--sa-ca-file: invalid value "", expected a path to a CA certificate file`,
		},
		"C spelling CA file": {
			args: []string{"--sa-cafile", ""},
			want: `--sa-cafile: invalid value "", expected a path to a CA certificate file`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, password := range []string{"admin", "secrets:aql:password"} {
				af, sa := parseToolFlags(t, append([]string{"-U", "admin", "-P", password}, tt.args...)...)
				require.EqualError(t, af.ResolveSecrets(t.Context(), sa), tt.want, password)
			}
		})
	}
}

func TestPasswordFlagTypeListsSources(t *testing.T) {
	t.Parallel()

	var flag PasswordFlag

	withSecrets := NewDefaultAerospikeFlags().NewFlagSetWithSecrets(DefaultWrapHelpString).Lookup("password")

	for _, source := range []string{"env:", "env-b64:", "b64:", "file:"} {
		require.True(t, strings.Contains(flag.Type(), source), source)
		require.True(t, strings.Contains(withSecrets.Value.Type(), source), source)
	}

	require.NotContains(t, flag.Type(), "secrets:")
	require.Contains(t, withSecrets.Value.Type(), "secrets:<resource>:<key>")
}

func TestCertFlagTypeListsSecrets(t *testing.T) {
	t.Parallel()

	var flag CertFlag

	fs := NewDefaultAerospikeFlags().NewFlagSetWithSecrets(DefaultWrapHelpString)

	require.NotContains(t, flag.Type(), "secrets:")

	for _, name := range []string{"tls-cafile", "tls-certfile", "tls-keyfile"} {
		require.Contains(t, fs.Lookup(name).Value.Type(), "secrets:<resource>:<key>", name)
	}
}

func TestNewFlagSetHelpOmitsSecrets(t *testing.T) {
	t.Parallel()

	require.NotContains(t, NewDefaultAerospikeFlags().NewFlagSet(DefaultWrapHelpString).FlagUsages(), "secrets:")

	fs := NewDefaultAerospikeFlags().NewFlagSetWithSecrets(DefaultWrapHelpString)

	names := []string{"user", "password", "tls-cafile", "tls-certfile", "tls-keyfile", "tls-keyfile-password"}

	for _, name := range names {
		flag := fs.Lookup(name)
		require.Contains(t, flag.Value.Type()+" "+flag.Usage, "secrets:<resource>:<key>", name)
	}
}

// collectWarnings sends af's warnings to the returned slice.
func collectWarnings(af *AerospikeFlags) *[]string {
	warnings := &[]string{}

	af.SetWarningHandler(func(msg string) { *warnings = append(*warnings, msg) })

	return warnings
}

func TestResolveSecretsReadsPasswordSources(t *testing.T) {
	t.Setenv("TCG_TEST_PASSWORD", "env-pass")

	keyPassFile := filepath.Join(t.TempDir(), "keypass")
	require.NoError(t, os.WriteFile(keyPassFile, []byte("key-pass\r\nsecond line\n"), 0o600))

	af, sa := parseToolFlags(t,
		"-U", "admin", "-P", "env:TCG_TEST_PASSWORD",
		"--tls-keyfile", "file:"+testFileDataPath, "--tls-keyfile-password", "file:"+keyPassFile,
		"--sa-address", unreachableAgent,
	)

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, "env-pass", string(af.Password))
	require.Equal(t, "key-pass", string(af.TLSKeyFilePass))

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, "env-pass", string(af.Password))
}

func TestResolveSecretsReadsSourcesOnce(t *testing.T) {
	t.Parallel()

	af, sa := parseToolFlags(t, "-U", "admin", "-P", "b64:"+encode("env:TCG_TEST_UNSET"))

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, "env:TCG_TEST_UNSET", string(af.Password))
}

func TestResolveSecretsTrimsKeyFilePassword(t *testing.T) {
	const space = " \t\n\v\f\r"

	t.Setenv("TCG_TEST_KP", "env-kp")
	t.Setenv("TCG_TEST_KP_B64", encode("env-b64-kp"))

	agent := newTestAgent(t)
	keyPassFile := writePasswordFile(t, " file kp \t\nsecond line\n")

	tests := map[string]struct {
		value string
		want  string
	}{
		"env":                   {value: " env:TCG_TEST_KP ", want: "env-kp"},
		"env-b64":               {value: "\tenv-b64:TCG_TEST_KP_B64\n", want: "env-b64-kp"},
		"b64":                   {value: "  b64:" + encode("b64-kp") + "\r\n", want: "b64-kp"},
		"file keeps first line": {value: " file:" + keyPassFile + " ", want: " file kp \t"},
		"secrets":               {value: " secrets:aql:keypass\t", want: resolvedKeyPass},
		"padded literal":        {value: "  " + literalKeyPass + " \t", want: literalKeyPass},
		"every ASCII space":     {value: space + literalKeyPass + space, want: literalKeyPass},
		"leading NBSP":          {value: nbsp + literalKeyPass, want: nbsp + literalKeyPass},
		"Unicode spaces kept":   {value: " " + nbsp + literalKeyPass + "\u0085 ", want: nbsp + literalKeyPass + "\u0085"},
		"NBSP before a source":  {value: nbsp + "env:TCG_TEST_KP", want: nbsp + "env:TCG_TEST_KP"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolFlags(t, "--tls-enable",
				"--tls-keyfile", "file:"+testFileDataPath, "--tls-keyfile-password", tt.value, "--sa-address", agent.Addr())

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, tt.want, string(af.TLSKeyFilePass))
		})
	}
}

func TestResolveSecretsKeepsPasswordWhitespace(t *testing.T) {
	t.Setenv("TCG_TEST_PASSWORD", "env-pass")

	for _, value := range []string{" env:TCG_TEST_PASSWORD ", " secrets:aql:password ", "  pass \t"} {
		t.Run(value, func(t *testing.T) {
			af, sa := parseToolFlags(t, "-U", "admin", "-P", value, "--sa-address", unreachableAgent)

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, value, string(af.Password))
		})
	}
}

func TestResolveSecretsTrimsKeyFilePasswordFromConfigFile(t *testing.T) {
	t.Setenv("TCG_TEST_KP", "env-kp")

	agent := newTestAgent(t)

	tests := map[string]struct {
		value string
		want  string
	}{
		"env":            {value: " env:TCG_TEST_KP ", want: "env-kp"},
		"b64":            {value: "\tb64:" + encode("b64-kp") + " ", want: "b64-kp"},
		"secrets":        {value: "\tsecrets:aql:keypass ", want: resolvedKeyPass},
		"padded literal": {value: "  " + literalKeyPass + " \t", want: literalKeyPass},
		"leading NBSP":   {value: nbsp + literalKeyPass, want: nbsp + literalKeyPass},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolConfig(t, fmt.Sprintf(
				"[cluster]\nuser = \"admin\"\npassword = %q\ntls-enable = true\ntls-keyfile = %q\ntls-keyfile-password = %q\n\n"+
					"[secret-agent]\nsa-address = %q\n", tt.value, testFileDataPath, tt.value, agent.Addr()))

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, tt.want, string(af.TLSKeyFilePass))
			require.Equal(t, tt.value, string(af.Password))
		})
	}
}

func TestResolveSecretsCommandLineLabels(t *testing.T) {
	t.Parallel()

	keyFile := []string{"--tls-keyfile", "file:" + testFileDataPath}

	tests := map[string]struct {
		want string
		args []string
	}{
		"--password": {
			args: []string{"-U", "admin", "-P", "env:"},
			want: "--password: env: requires a variable name",
		},
		"key file password": {
			args: append([]string{"--tls-keyfile-password", "env-b64:"}, keyFile...),
			want: "--tls-keyfile-password: env-b64: requires a variable name",
		},
		"key file password after the key file": {
			args: append(append([]string{}, keyFile...), "--tls-keyfile-password", "file:"),
			want: "--tls-keyfile-password: file: requires a path",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, tt.args...)
			require.EqualError(t, af.ResolveSecrets(t.Context(), sa), tt.want)
		})
	}
}

func TestResolveSecretsConfigFileLabels(t *testing.T) {
	tests := map[string]struct {
		conf     string
		instance string
		want     string
		password string
		args     []string
	}{
		"config file password": {
			conf: "[cluster]\nuser = \"admin\"\npassword = \"file:\"\n",
			want: "password in config file: file: requires a path",
		},
		"key file password": {
			conf: fmt.Sprintf("[cluster]\ntls-keyfile = %q\ntls-keyfile-password = \"env:\"\n", testFileDataPath),
			want: "tls-keyfile-password in config file: env: requires a variable name",
		},
		"instance section": {
			conf: "[cluster]\nuser = \"admin\"\npassword = \"admin\"\n\n" +
				"[cluster_x]\nuser = \"admin\"\npassword = \"b64:\"\n",
			instance: "x",
			want:     "password in config file: password from b64: value is empty",
		},
		"user on the command line": {
			conf: "[cluster]\npassword = \"env:\"\n",
			args: []string{"-U", "admin"},
			want: "password in config file: env: requires a variable name",
		},
		"command line beats a bad config file value": {
			conf:     "[cluster]\nuser = \"admin\"\npassword = \"env:\"\n",
			args:     []string{"-P", "b64:" + encode("cli-pass")},
			password: "cli-pass",
		},
		"bad command line value beats the config file": {
			conf: "[cluster]\nuser = \"admin\"\npassword = \"admin\"\n",
			args: []string{"-P", "env-b64:"},
			want: "--password: env-b64: requires a variable name",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolConfigArgs(t, tt.conf, tt.instance, tt.args...)

			err := af.ResolveSecrets(t.Context(), sa)
			if tt.want != "" {
				require.EqualError(t, err, tt.want)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.password, string(af.Password))
		})
	}
}

func TestResolveSecretsNoUserWarning(t *testing.T) {
	t.Parallel()

	const ignored = "--password: ignored because no user is set"

	tests := map[string]struct {
		want string
		args []string
	}{
		"env source":     {args: []string{"-P", "env:TCG_TEST_UNSET"}, want: ignored},
		"env-b64 source": {args: []string{"-P", "env-b64:TCG_TEST_UNSET"}, want: ignored},
		"b64 source":     {args: []string{"-P", "b64:"}, want: ignored},
		"file source":    {args: []string{"-P", "file:/missing"}, want: ignored},
		"literal":        {args: []string{"-P", "admin"}},
		"secret":         {args: []string{"-P", "secrets:aql:password"}, want: ignored},
		"auth pki":       {args: []string{"--auth", "pki", "-P", "env:TCG_TEST_UNSET"}},
		"no password, key file password source": {
			args: []string{"--tls-keyfile-password", "env:TCG_TEST_UNSET"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, append(tt.args, "--sa-address", unreachableAgent)...)
			warnings := collectWarnings(af)

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Empty(t, af.Password)
			require.Empty(t, af.TLSKeyFilePass)

			if tt.want == "" {
				require.Empty(t, *warnings)
			} else {
				require.Equal(t, []string{tt.want}, *warnings)
			}
		})
	}
}

func TestResolveSecretsNoUserWarningFromConfigFile(t *testing.T) {
	af, sa := parseToolConfig(t, "[cluster]\npassword = \"file:/missing\"\n")
	warnings := collectWarnings(af)

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, []string{"password in config file: ignored because no user is set"}, *warnings)
}

func TestResolveSecretsNoUserWarningForSecretFromConfigFile(t *testing.T) {
	af, sa := parseToolConfig(t, fmt.Sprintf(
		"[cluster]\npassword = \"secrets:aql:password\"\n\n[secret-agent]\nsa-address = %q\n", unreachableAgent))
	warnings := collectWarnings(af)

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Empty(t, af.Password)
	require.Equal(t, []string{"password in config file: ignored because no user is set"}, *warnings)
}

func TestResolveSecretsPKISkipsPassword(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"source":       {"-P", "env:TCG_TEST_UNSET"},
		"long literal": {"-P", strings.Repeat("p", passwordMaxLen+1)},
		"secret":       {"-P", "secrets:aql:password", "--sa-address", unreachableAgent},
	}

	for name, args := range tests {
		for _, auth := range []string{"PKI", "pki", "Pki"} {
			t.Run(name+" "+auth, func(t *testing.T) {
				t.Parallel()

				af, sa := parseToolFlags(t, append([]string{"-U", "admin", "--auth", auth}, args...)...)
				warnings := collectWarnings(af)

				require.NoError(t, af.ResolveSecrets(t.Context(), sa))
				require.Empty(t, af.Password)
				require.Empty(t, *warnings)
			})
		}
	}
}

func TestResolveSecretsKeyFilePasswordNeedsKeyFile(t *testing.T) {
	t.Parallel()

	af, sa := parseToolFlags(t, "--tls-keyfile-password", "env:TCG_TEST_UNSET")

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Empty(t, af.TLSKeyFilePass)
}

func TestResolveSecretsPasswordLimits(t *testing.T) {
	t.Parallel()

	at63, over63 := strings.Repeat("p", passwordMaxLen), strings.Repeat("p", passwordMaxLen+1)
	at1024, over1024 := strings.Repeat("k", tlsKeyFilePasswordMaxLen), strings.Repeat("k", tlsKeyFilePasswordMaxLen+1)

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{
		"aql": {"at63": encode(at63), "over63": encode(over63), "at1024": encode(at1024), "over1024": encode(over1024)},
	})

	user := []string{"-U", "admin", "--sa-address", agent.Addr()}
	keyFile := []string{"--tls-enable", "--tls-keyfile", "file:" + testFileDataPath, "--sa-address", agent.Addr()}

	tests := map[string]struct {
		want string
		args []string
	}{
		"literal 63":   {args: append([]string{"-P", at63}, user...)},
		"secret 63":    {args: append([]string{"-P", "secrets:aql:at63"}, user...)},
		"literal 1024": {args: append([]string{"--tls-keyfile-password", at1024}, keyFile...)},
		"secret 1024":  {args: append([]string{"--tls-keyfile-password", "secrets:aql:at1024"}, keyFile...)},
		"literal 64": {
			args: append([]string{"-P", over63}, user...),
			want: "--password: password is longer than 63 bytes",
		},
		"secret 64": {
			args: append([]string{"-P", "secrets:aql:over63"}, user...),
			want: "--password: password is longer than 63 bytes",
		},
		"source 64": {
			args: append([]string{"-P", "b64:" + encode(over63)}, user...),
			want: "--password: decoded b64: value is longer than 63 bytes",
		},
		"literal 1025": {
			args: append([]string{"--tls-keyfile-password", over1024}, keyFile...),
			want: "--tls-keyfile-password: password is longer than 1024 bytes",
		},
		"secret 1025": {
			args: append([]string{"--tls-keyfile-password", "secrets:aql:over1024"}, keyFile...),
			want: "--tls-keyfile-password: password is longer than 1024 bytes",
		},
		"source 1025": {
			args: append([]string{"--tls-keyfile-password", "b64:" + encode(over1024)}, keyFile...),
			want: "--tls-keyfile-password: decoded b64: value is longer than 1024 bytes",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, tt.args...)

			err := af.ResolveSecrets(t.Context(), sa)
			if tt.want != "" {
				require.EqualError(t, err, tt.want)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestResolveSecretsPasswordLimitsFromConfigFile(t *testing.T) {
	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{
		"aql": {"over63": encode(strings.Repeat("p", passwordMaxLen+1))},
	})

	af, sa := parseToolConfig(t, fmt.Sprintf(
		"[cluster]\nuser = \"admin\"\npassword = \"secrets:aql:over63\"\n\n[secret-agent]\nsa-address = %q\n", agent.Addr()))
	require.EqualError(t, af.ResolveSecrets(t.Context(), sa), "password in config file: password is longer than 63 bytes")

	af, sa = parseToolConfig(t, fmt.Sprintf("[cluster]\nuser = \"admin\"\npassword = %q\n",
		strings.Repeat("p", passwordMaxLen+1)))
	require.EqualError(t, af.ResolveSecrets(t.Context(), sa), "password in config file: password is longer than 63 bytes")
}

func TestResolveSecretsFetchErrorFromConfigFile(t *testing.T) {
	agent := newTestAgent(t)

	af, sa := parseToolConfig(t, fmt.Sprintf(
		"[cluster]\nuser = \"admin\"\npassword = \"secrets:aql:missing\"\n\n[secret-agent]\nsa-address = %q\n", agent.Addr()))

	err := af.ResolveSecrets(t.Context(), sa)
	require.ErrorIs(t, err, secretagent.ErrRequestFailed)
	require.True(t, strings.HasPrefix(err.Error(), "password in config file: "), err.Error())
}

func TestResolveSecretsRejectsNUL(t *testing.T) {
	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{"aql": {"nul": encode("a\x00b")}})

	af, sa := parseToolFlags(t, "-U", "admin", "-P", "secrets:aql:nul", "--sa-address", agent.Addr())
	require.EqualError(t, af.ResolveSecrets(t.Context(), sa), "--password: password contains a NUL byte")

	af, sa = parseToolFlags(t, "--tls-enable", "--tls-keyfile", "file:"+testFileDataPath,
		"--tls-keyfile-password", "secrets:aql:nul", "--sa-address", agent.Addr())
	require.EqualError(t, af.ResolveSecrets(t.Context(), sa), "--tls-keyfile-password: password contains a NUL byte")

	af, sa = parseToolConfig(t, "[cluster]\nuser = \"admin\"\npassword = \"a\\u0000b\"\n")
	require.EqualError(t, af.ResolveSecrets(t.Context(), sa), "password in config file: password contains a NUL byte")
}

func TestResolveSecretsWarnsOnStderrByDefault(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	stderr := os.Stderr
	os.Stderr = w

	t.Cleanup(func() { os.Stderr = stderr })

	af, sa := parseToolFlags(t, "-P", "env:TCG_TEST_UNSET", "--sa-address", unreachableAgent)
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.NoError(t, w.Close())

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "Warning: --password: ignored because no user is set\n", string(out))
}

func TestNewFlagSetWithSecretsPasswordUsage(t *testing.T) {
	t.Parallel()

	fs := NewDefaultAerospikeFlags().NewFlagSetWithSecrets(DefaultWrapHelpString)

	require.Equal(t, []string{
		"Password used to authenticate with cluster. Default: none",
		"It can be one of the following:",
		"1) Environment variable: 'env:<VAR>', used exactly as set",
		"2) Base64 encoded environment variable: 'env-b64:<VAR>'",
		"3) Base64 encoded string: 'b64:<BASE64>'",
		`4) File: 'file:<PATH>', the whole file less one trailing '\n' or`,
		`   '\r\n'. PATH should name a regular file.`,
		"5) Aerospike Secret Agent: 'secrets:<resource>:<key>'",
		"6) String: 'PASSWORD'",
		"Prefixes are case-sensitive. A base64 value may be line wrapped,",
		"and one trailing newline is dropped after decoding. A 'b64:' value",
		"on the command line is as visible as a literal password.",
		"A password that itself begins with 'env:', 'env-b64:', 'b64:',",
		"'file:' or 'secrets:' must be given as 'b64:'.",
		"The password is read only when a user is set and the auth mode is",
		"not PKI. It must be at most 63 bytes.",
		"A value fetched with 'secrets:' is used as-is.",
	}, strings.Split(fs.Lookup("password").Usage, "\n"))

	require.Equal(t, []string{
		"Password to load protected tls-keyfile.",
		"It can be one of the following:",
		"1) Environment variable: 'env:<VAR>', used exactly as set",
		"2) Base64 encoded environment variable: 'env-b64:<VAR>'",
		"3) Base64 encoded string: 'b64:<BASE64>'",
		"4) File: 'file:<PATH>', the first line of the file",
		"5) Aerospike Secret Agent: 'secrets:<resource>:<key>'",
		"6) String: 'PASSWORD'",
		"Prefixes are case-sensitive. A base64 value may be line wrapped,",
		"and one trailing newline is dropped after decoding.",
		"A password that itself begins with 'env:', 'env-b64:', 'b64:',",
		"'file:' or 'secrets:' must be given as 'b64:'.",
		"Surrounding whitespace is trimmed before the form is read. A",
		"password with surrounding whitespace must be given as 'b64:'.",
		"The password is read only when a key file is set. It must be at",
		"most 1024 bytes.",
		"A value fetched with 'secrets:' is used as-is.",
		"Default: none",
	}, strings.Split(fs.Lookup("tls-keyfile-password").Usage, "\n"))

	require.Contains(t, fs.FlagUsages(), "-P, --password "+fs.Lookup("password").Value.Type())
}

func TestNewFlagSetKeepsPasswordUsage(t *testing.T) {
	t.Parallel()

	fs := NewDefaultAerospikeFlags().NewFlagSet(func(usage string) string { return usage })

	require.Equal(t, "The Aerospike password for the connection to the Aerospike cluster.", fs.Lookup("password").Usage)
	require.Equal(t, "The password used to decrypt the key file if encrypted.", fs.Lookup("tls-keyfile-password").Usage)
}

// NewFlagSet keeps reading password sources as the flags are parsed.
func TestNewFlagSetReadsPasswordWhenParsed(t *testing.T) {
	t.Setenv("TCG_TEST_PASSWORD", "env-pass")

	af := NewDefaultAerospikeFlags()
	require.NoError(t, af.NewFlagSet(DefaultWrapHelpString).Parse([]string{"-P", "env:TCG_TEST_PASSWORD"}))
	require.Equal(t, "env-pass", string(af.Password))
}

func TestResolveSecretsSkipsTLSSecretsWithoutTLS(t *testing.T) {
	agent := newTestAgent(t)
	addr, conns := newProxy(t, "127.0.0.1:0", agent.Addr())

	tests := map[string][]string{
		"CA file":   {"--tls-cafile", "secrets:aql:ca"},
		"cert file": {"--tls-certfile", "secrets:aql:ca"},
		"key file":  {"--tls-keyfile", "secrets:aql:ca"},
		"key file password": {
			"--tls-keyfile", "file:" + testFileDataPath, "--tls-keyfile-password", "secrets:aql:keypass",
		},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolFlags(t, append(args, "--sa-address", addr)...)

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Zero(t, conns.Load())
		})
	}

	af, sa := parseToolConfig(t, fmt.Sprintf(
		"[cluster]\ntls-cafile = \"secrets:aql:ca\"\ntls-keyfile = %q\ntls-keyfile-password = \"secrets:aql:keypass\"\n\n"+
			"[secret-agent]\nsa-address = %q\n", testFileDataPath, addr))

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Zero(t, conns.Load())
}

func TestResolveSecretsConfigMergedWithCommandLine(t *testing.T) {
	agent := newTestAgent(t)
	addr, conns := newProxy(t, "127.0.0.1:0", agent.Addr())

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	conf := fmt.Sprintf("[cluster]\nuser = \"secrets:aql:user\"\npassword = \"secrets:aql:missing\"\n\n"+
		"[secret-agent]\nsa-address = %q\n", host)

	af, sa := parseToolConfigArgs(t, conf, "", "--sa-port", port, "-P", "cli-pass")

	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedUser, af.User)
	require.Equal(t, "cli-pass", string(af.Password))
	require.EqualValues(t, 1, conns.Load())
}

func TestResolveSecretsFetchedValuesUsedAsIs(t *testing.T) {
	t.Parallel()

	values := []string{" env:HOME ", "b64:" + encode("x"), "file:" + testFileDataPath, "secrets:aql:password"}

	secrets := map[string]string{}
	for i, value := range values {
		secrets[fmt.Sprint(i)] = encode(value)
	}

	agent := secretagenttest.NewServer(t, secretagenttest.Secrets{"aql": secrets})

	for i, value := range values {
		ref := fmt.Sprintf("secrets:aql:%d", i)

		t.Run(value, func(t *testing.T) {
			t.Parallel()

			af, sa := parseToolFlags(t, "-U", ref, "-P", ref, "--tls-enable", "--tls-keyfile", "file:"+testFileDataPath,
				"--tls-keyfile-password", ref, "--sa-address", agent.Addr())

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, value, af.User)
			require.Equal(t, value, string(af.Password))
			require.Equal(t, value, string(af.TLSKeyFilePass))
		})
	}
}
