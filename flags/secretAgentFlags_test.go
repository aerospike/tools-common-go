package flags

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSecretAgentAddress(t *testing.T) {
	t.Parallel()

	valid := map[string][2]string{
		"127.0.0.1":            {"127.0.0.1", ""},
		"127.0.0.1:4000":       {"127.0.0.1", "4000"},
		"agent.example.com:1":  {"agent.example.com", "1"},
		"localhost:65535":      {"localhost", "65535"},
		"::1":                  {"::1", ""},
		"fe80::1%lo0":          {"fe80::1%lo0", ""},
		"[::1]":                {"::1", ""},
		"[::1]:4000":           {"::1", "4000"},
		"[fe80::1%lo0]:3005":   {"fe80::1%lo0", "3005"},
		"[2001:db8::1]:3005":   {"2001:db8::1", "3005"},
		"agent-1.internal:300": {"agent-1.internal", "300"},
	}

	for address, want := range valid {
		host, port, ok := parseSecretAgentAddress(address)
		require.True(t, ok, address)
		require.Equal(t, want, [2]string{host, port}, address)
	}

	invalid := []string{
		"", ":3005", "host:", "host:0", "host:65536", "host:+1", "host:x",
		"host:3005:x", "10.0.0.1:3005:1", "[]:3005", "[::1", "[::1]x", "[::1]:",
		"[host:3005:x]", "[host:3005:x]:3005", "[fe80::1%]:3005", "fe80::1%",
		"[localhost]:3005", "[127.0.0.1]:3005",
	}

	for _, address := range invalid {
		_, _, ok := parseSecretAgentAddress(address)
		require.False(t, ok, address)
	}
}

// parseSecretAgentFlags parses args as the command line, then applies config
// values the way config.SetFlags does: through Set, without marking the flag
// as changed, and only for flags not on the command line.
func parseSecretAgentFlags(t *testing.T, args []string, config map[string]string) *SecretAgentFlags {
	t.Helper()

	sa := NewDefaultSecretAgentFlags()
	fs := sa.NewFlagSet(DefaultWrapHelpString)
	require.NoError(t, fs.Parse(args))

	for name, value := range config {
		if !fs.Changed(name) {
			require.NoError(t, fs.Lookup(name).Value.Set(value))
		}
	}

	return sa
}

func TestSecretAgentAddressPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		config map[string]string
		name   string
		want   string
		args   []string
	}{
		{name: "defaults", want: "127.0.0.1:3005"},
		{name: "address", args: []string{"--sa-address", "agent"}, want: "agent:3005"},
		{name: "address with port", args: []string{"--sa-address", "agent:4000"}, want: "agent:4000"},
		{name: "port", args: []string{"--sa-port", "4000"}, want: "127.0.0.1:4000"},
		{name: "ipv6", args: []string{"--sa-address", "[::1]:4000"}, want: "[::1]:4000"},
		{
			name: "explicit port beats address port",
			args: []string{"--sa-address", "agent:4000", "--sa-port", "5000"},
			want: "agent:5000",
		},
		{
			name:   "config: explicit port beats address port",
			config: map[string]string{"sa-address": "agent:4000", "sa-port": "5000"},
			want:   "agent:5000",
		},
		{
			name:   "command line address port beats config port",
			args:   []string{"--sa-address", "agent:4000"},
			config: map[string]string{"sa-port": "5000"},
			want:   "agent:4000",
		},
		{
			name:   "command line port beats config address port",
			args:   []string{"--sa-port", "5000"},
			config: map[string]string{"sa-address": "agent:4000"},
			want:   "agent:5000",
		},
		{
			name:   "config port applies to command line address without port",
			args:   []string{"--sa-address", "agent"},
			config: map[string]string{"sa-port": "5000"},
			want:   "agent:5000",
		},
		{
			name:   "command line beats config",
			args:   []string{"--sa-address", "cli:4000"},
			config: map[string]string{"sa-address": "conf:5000"},
			want:   "cli:4000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			address, err := parseSecretAgentFlags(t, tt.args, tt.config).address()
			require.NoError(t, err)
			require.Equal(t, tt.want, address)
		})
	}
}

func TestSecretAgentFlagsValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want string
		args []string
	}{
		"address":      {args: []string{"--sa-address", "host:3005:x"}, want: "--sa-address: invalid value host:3005:x"},
		"port":         {args: []string{"--sa-port", "0"}, want: "--sa-port: invalid value 0"},
		"port range":   {args: []string{"--sa-port", "70000"}, want: "--sa-port: invalid value 70000"},
		"zero timeout": {args: []string{"--sa-timeout", "0"}, want: "--sa-timeout: invalid value 0"},
		"neg timeout":  {args: []string{"--sa-timeout", "-5"}, want: "--sa-timeout: invalid value -5"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := parseSecretAgentFlags(t, tt.args, nil).Validate()
			require.ErrorContains(t, err, tt.want)
		})
	}

	require.NoError(t, NewDefaultSecretAgentFlags().Validate())
}

func TestSecretAgentFlagSet(t *testing.T) {
	t.Parallel()

	sa := NewDefaultSecretAgentFlags()
	fs := sa.NewFlagSet(DefaultWrapHelpString)

	require.NoError(t, fs.Parse([]string{
		"--sa-address", "agent", "--sa-port", "4000", "--sa-timeout", "250", "--sa-ca-file", "/ca.pem",
	}))
	require.Equal(t, "agent", sa.Address)
	require.Equal(t, "4000", sa.Port)
	require.Equal(t, 250, sa.Timeout)
	require.Equal(t, "/ca.pem", sa.CAFile)
	require.Equal(t, "1000", fs.Lookup("sa-timeout").DefValue)
}
