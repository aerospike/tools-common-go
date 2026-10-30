package flags

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/aerospike/tools-common-go/secretagent/secretagenttest"
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

func TestSecretAgentCAFilePrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		config map[string]string
		name   string
		want   string
		args   []string
	}{
		{name: "none"},
		{name: "command line C spelling", args: []string{"--sa-cafile", "/c.pem"}, want: "/c.pem"},
		{name: "config C spelling", config: map[string]string{"sa-cafile": "/c.pem"}, want: "/c.pem"},
		{
			name: "command line: --sa-ca-file beats --sa-cafile",
			args: []string{"--sa-cafile", "/c.pem", "--sa-ca-file", "/go.pem"},
			want: "/go.pem",
		},
		{
			name:   "config: sa-ca-file beats sa-cafile",
			config: map[string]string{"sa-ca-file": "/go.pem", "sa-cafile": "/c.pem"},
			want:   "/go.pem",
		},
		{
			name:   "command line --sa-ca-file beats config sa-cafile",
			args:   []string{"--sa-ca-file", "/cli.pem"},
			config: map[string]string{"sa-cafile": "/conf.pem"},
			want:   "/cli.pem",
		},
		{
			name:   "command line --sa-cafile beats config sa-ca-file",
			args:   []string{"--sa-cafile", "/cli.pem"},
			config: map[string]string{"sa-ca-file": "/conf.pem"},
			want:   "/cli.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, parseSecretAgentFlags(t, tt.args, tt.config).caFile())
		})
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	stderr := os.Stderr
	os.Stderr = w

	defer func() { os.Stderr = stderr }()

	fn()

	require.NoError(t, w.Close())

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	return string(out)
}

func TestSecretAgentCAFileCSpellingDeprecated(t *testing.T) {
	pki, err := secretagenttest.GeneratePKI(t.TempDir())
	require.NoError(t, err)

	var fs *pflag.FlagSet

	out := captureStderr(t, func() {
		sa := NewDefaultSecretAgentFlags()
		fs = sa.NewFlagSet(DefaultWrapHelpString)

		require.NoError(t, fs.Parse([]string{"--sa-cafile", pki.CAFile}))
		require.NoError(t, sa.Validate())

		_, clientErr := sa.NewClient()
		require.NoError(t, clientErr)
	})

	require.Equal(t, "Warning: Argument --sa-cafile is deprecated. Use --sa-ca-file instead.\n", out)
	require.True(t, fs.Lookup("sa-cafile").Hidden)
	require.NotContains(t, fs.FlagUsages(), "sa-cafile")

	out = captureStderr(t, func() {
		_, sa := parseToolConfig(t, fmt.Sprintf("[secret-agent]\nsa-cafile = %q\n", pki.CAFile))

		_, clientErr := sa.NewClient()
		require.NoError(t, clientErr)
	})

	require.Empty(t, out)
}

func TestSecretAgentFlagsValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want string
		args []string
	}{
		"address": {
			args: []string{"--sa-address", "host:3005:x"},
			want: `--sa-address: invalid value "host:3005:x", expected <host>[:<port>] or [<ipv6>][:<port>]`,
		},
		"port": {
			args: []string{"--sa-port", "0"},
			want: `--sa-port: invalid value "0", expected an integer from 1 to 65535`,
		},
		"port range":   {args: []string{"--sa-port", "70000"}, want: `--sa-port: invalid value "70000"`},
		"zero timeout": {args: []string{"--sa-timeout", "0"}, want: `--sa-timeout: invalid value "0"`},
		"neg timeout":  {args: []string{"--sa-timeout", "-5"}, want: `--sa-timeout: invalid value "-5"`},
		"huge timeout": {
			args: []string{"--sa-timeout", "9223372036854775807"},
			want: `--sa-timeout: invalid value "9223372036854775807", expected an integer from 1 to 2147483647`,
		},
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

func TestSecretAgentNewClientInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want string
		args []string
	}{
		"address": {args: []string{"--sa-address", "host:"}, want: `--sa-address: invalid value "host:"`},
		"timeout": {args: []string{"--sa-timeout", "0"}, want: `--sa-timeout: invalid value "0"`},
		"CA file": {args: []string{"--sa-ca-file", "/missing.pem"}, want: `--sa-ca-file: cannot load CA file "/missing.pem": no such file or directory`},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client, err := parseSecretAgentFlags(t, tt.args, nil).NewClient()
			require.ErrorContains(t, err, tt.want)
			require.Nil(t, client)
		})
	}
}

func TestSecretAgentFlagsWithoutFlagSet(t *testing.T) {
	t.Parallel()

	sa := &SecretAgentFlags{Address: "agent:4000", Port: "5000", Timeout: 250}

	address, err := sa.address()
	require.NoError(t, err)
	require.Equal(t, "agent:5000", address)

	client, err := sa.NewClient()
	require.NoError(t, err)
	require.NotNil(t, client)
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

func TestSecretAgentEmptyCAFile(t *testing.T) {
	agent := newTestAgent(t)
	addr, conns := newProxy(t, "127.0.0.1:0", agent.Addr())

	tests := map[string]struct {
		conf string
		want string
		args []string
	}{
		"--sa-ca-file":      {args: []string{"--sa-ca-file", ""}, want: "--sa-ca-file"},
		"--sa-ca-file=":     {args: []string{"--sa-ca-file="}, want: "--sa-ca-file"},
		"--sa-cafile":       {args: []string{"--sa-cafile", ""}, want: "--sa-cafile"},
		"config sa-ca-file": {conf: "sa-ca-file = \"\"\n", want: "sa-ca-file in the [secret-agent] config section"},
		"config sa-cafile":  {conf: "sa-cafile = \"\"\n", want: "sa-cafile in the [secret-agent] config section"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := conns.Load()

			err := resolveToolConfig(t, "[cluster]\nuser = \"secrets:aql:user\"\n\n[secret-agent]\n"+tt.conf, "",
				append([]string{"--sa-address", addr}, tt.args...)...)

			require.ErrorContains(t, err, tt.want)
			require.Equal(t, before, conns.Load())
		})
	}
}

func TestSecretAgentConfigFailsClosed(t *testing.T) {
	agent := newTestAgent(t)
	addr, conns := newProxy(t, "127.0.0.1:0", agent.Addr())

	const (
		section = " in the [secret-agent] config section"
		address = section + ", expected <host>[:<port>] or [<ipv6>][:<port>]"
		port    = section + ", expected an integer from 1 to 65535"
		timeout = section + ", expected an integer from 1 to 2147483647"
		caFile  = section + ", expected a path to a CA certificate file"
	)

	tests := map[string]struct {
		conf     string
		instance string
		want     string
	}{
		"unknown key":         {conf: "sa-ca-flie = \"/ca.pem\"", want: "unknown key sa-ca-flie" + section},
		"unknown key, number": {conf: "bogus = 1", want: "unknown key bogus" + section},
		"port array":          {conf: "sa-port = [3005]", want: `invalid value "[3005]" for sa-port` + port},
		"port float":          {conf: "sa-port = 3005.5", want: `invalid value "3005.5" for sa-port` + port},
		"port bool":           {conf: "sa-port = true", want: `invalid value "true" for sa-port` + port},
		"port zero":           {conf: "sa-port = 0", want: `invalid value "0" for sa-port` + port},
		"port empty":          {conf: "sa-port = \"\"", want: `invalid value "" for sa-port` + port},
		"port too long":       {conf: "sa-port = \"003005\"", want: `invalid value "003005" for sa-port` + port},
		"timeout zero":        {conf: "sa-timeout = 0", want: `invalid value "0" for sa-timeout` + timeout},
		"timeout array":       {conf: "sa-timeout = [1000]", want: `invalid value "[1000]" for sa-timeout` + timeout},
		"address":             {conf: "sa-address = \"a:b:c\"", want: `invalid value "a:b:c" for sa-address` + address},
		"address number":      {conf: "sa-address = 123", want: `invalid value "123" for sa-address` + address},
		"address array": {
			conf: "sa-address = [\"10.0.0.1\"]", want: `invalid value "[10.0.0.1]" for sa-address` + address,
		},
		"address empty": {conf: "sa-address = \"\"", want: `invalid value "" for sa-address` + address},
		"address space": {
			conf: "sa-address = \" 127.0.0.1\"", want: `invalid value " 127.0.0.1" for sa-address` + address,
		},
		"CA file number":      {conf: "sa-ca-file = 1", want: `invalid value "1" for sa-ca-file` + caFile},
		"C spelling CA array": {conf: "sa-cafile = [\"/ca.pem\"]", want: `invalid value "[/ca.pem]" for sa-cafile` + caFile},
		"instance unknown key": {
			conf: "[secret-agent_x]\nsa-host = \"agent\"", instance: "x",
			want: "unknown key sa-host in the [secret-agent_x] config section",
		},
		"instance port": {
			conf: "[secret-agent_x]\nsa-port = 0", instance: "x",
			want: `invalid value "0" for sa-port in the [secret-agent_x] config section, expected an integer from 1 to 65535`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conf := tt.conf
			if !strings.HasPrefix(conf, "[") {
				conf = "[secret-agent]\n" + conf
			}

			_, _, err := loadToolConfig(t, "[cluster]\nuser = \"admin\"\npassword = \"admin\"\n\n"+conf+"\n", tt.instance)
			require.ErrorContains(t, err, tt.want)

			before := conns.Load()

			af, sa, err := loadToolConfig(t, conf+"\n", tt.instance, "--sa-address", addr, "-U", "secrets:aql:user")
			if err == nil {
				_ = af.ResolveSecrets(t.Context(), sa)
			}

			require.ErrorContains(t, err, tt.want)
			require.Equal(t, before, conns.Load())
		})
	}
}

func TestSecretAgentTimeoutDecimalOnly(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"0x10", "+5", "1_000", " 5", "5 ", "0b11", "0o17", "٥", "1.5", "1e3", "00"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			err := parseSecretAgentFlags(t, []string{"--sa-timeout", value}, nil).Validate()
			require.EqualError(t, err, `--sa-timeout: invalid value "`+value+`", expected an integer from 1 to 2147483647`)
		})
	}

	for value, want := range map[string]int{"1": 1, "010": 10, "0900": 900, "2147483647": 2147483647} {
		sa := parseSecretAgentFlags(t, []string{"--sa-timeout", value}, nil)
		require.NoError(t, sa.Validate(), value)
		require.Equal(t, want, sa.Timeout, value)
	}
}

func TestSecretAgentConfigTimeoutDecimalOnly(t *testing.T) {
	const want = " for sa-timeout in the [secret-agent] config section, expected an integer from 1 to 2147483647"

	invalid := map[string]string{
		`"0x10"`:     "0x10",
		`"+5"`:       "+5",
		`" 5"`:       " 5",
		`"1.5"`:      "1.5",
		`1.0`:        "1.0",
		`1.5`:        "1.5",
		`true`:       "true",
		`-5`:         "-5",
		`2147483648`: "2147483648",
	}

	for value, shown := range invalid {
		t.Run(value, func(t *testing.T) {
			_, _, err := loadToolConfig(t, "[secret-agent]\nsa-timeout = "+value+"\n", "")
			require.EqualError(t, err, `invalid value "`+shown+`"`+want)
		})
	}

	valid := map[string]int{`1000`: 1000, `"1000"`: 1000, `"010"`: 10, `"0900"`: 900, `2147483647`: 2147483647}

	for value, want := range valid {
		t.Run(value, func(t *testing.T) {
			_, sa, err := loadToolConfig(t, "[secret-agent]\nsa-timeout = "+value+"\n", "")
			require.NoError(t, err)
			require.NoError(t, sa.Validate())
			require.Equal(t, want, sa.Timeout)
		})
	}
}

func TestSecretAgentAddressAcrossSources(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want string
		args []string
	}{
		{
			name: "config address port, command line host",
			conf: `sa-address = "h:4100"`, args: []string{"--sa-address", "h2"}, want: "h2:4100",
		},
		{
			name: "config address port, command line IPv6 host",
			conf: `sa-address = "h:4100"`, args: []string{"--sa-address", "::1"}, want: "[::1]:4100",
		},
		{
			name: "config port beats config address port",
			conf: "sa-address = \"h:4100\"\nsa-port = \"5000\"", args: []string{"--sa-address", "h2"}, want: "h2:5000",
		},
		{name: "config only", conf: "sa-address = \"h:4100\"\nsa-port = 5000", want: "h:5000"},
		{
			name: "command line port beats command line address port",
			conf: `sa-address = "h:4100"`, args: []string{"--sa-address", "h2:4200", "--sa-port", "4300"}, want: "h2:4300",
		},
		{
			name: "command line address port beats config port",
			conf: `sa-port = 5000`, args: []string{"--sa-address", "h2:4200"}, want: "h2:4200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, sa := parseToolConfigArgs(t, "[secret-agent]\n"+tt.conf+"\n", "", tt.args...)

			address, err := sa.address()
			require.NoError(t, err)
			require.Equal(t, tt.want, address)
		})
	}
}

func TestSecretAgentErrorLabels(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pem")

	tests := map[string]struct {
		conf     string
		instance string
		want     string
		notWant  string
		args     []string
	}{
		"--sa-cafile":  {args: []string{"--sa-cafile", missing}, want: "--sa-cafile: ", notWant: "--sa-ca-file"},
		"--sa-ca-file": {args: []string{"--sa-ca-file", missing}, want: "--sa-ca-file: "},
		"config sa-cafile": {
			conf: fmt.Sprintf("[secret-agent]\nsa-cafile = %q\n", missing),
			want: "sa-cafile in the [secret-agent] config section", notWant: "--sa",
		},
		"config sa-ca-file": {
			conf: fmt.Sprintf("[secret-agent]\nsa-ca-file = %q\n", missing),
			want: "sa-ca-file in the [secret-agent] config section", notWant: "--sa",
		},
		"instance sa-ca-file": {
			conf:     fmt.Sprintf("[secret-agent_x]\nsa-ca-file = %q\n", missing),
			instance: "x",
			want:     "sa-ca-file in the [secret-agent_x] config section", notWant: "--sa",
		},
		"config sa-port": {
			conf:    "[secret-agent]\nsa-port = \"0\"\n",
			want:    `invalid value "0" for sa-port in the [secret-agent] config section, expected an integer from 1 to 65535`,
			notWant: "--sa",
		},
		"config sa-timeout": {
			conf: "[secret-agent]\nsa-timeout = 0\n",
			want: `invalid value "0" for sa-timeout in the [secret-agent] config section,` +
				" expected an integer from 1 to 2147483647",
			notWant: "--sa",
		},
		"config sa-address": {
			conf: "[secret-agent]\nsa-address = \"host:\"\n",
			want: `invalid value "host:" for sa-address in the [secret-agent] config section,` +
				" expected <host>[:<port>] or [<ipv6>][:<port>]",
			notWant: "--sa",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := resolveToolConfig(t, tt.conf, tt.instance,
				append([]string{"--sa-address", unreachableAgent, "-U", "secrets:aql:user"}, tt.args...)...)

			require.ErrorContains(t, err, tt.want)

			if tt.notWant != "" {
				require.NotContains(t, err.Error(), tt.notWant)
			}
		})
	}
}

func TestSecretAgentFlagsValidateStrict(t *testing.T) {
	t.Parallel()

	const (
		address = ", expected <host>[:<port>] or [<ipv6>][:<port>]"
		port    = ", expected an integer from 1 to 65535"
	)

	tests := map[string]struct {
		want string
		args []string
	}{
		"leading space": {
			args: []string{"--sa-address", " 127.0.0.1"}, want: `--sa-address: invalid value " 127.0.0.1"` + address,
		},
		"inner space": {
			args: []string{"--sa-address", "host name"}, want: `--sa-address: invalid value "host name"` + address,
		},
		"trailing tab": {
			args: []string{"--sa-address", "127.0.0.1\t"}, want: "--sa-address: invalid value \"127.0.0.1\t\"" + address,
		},
		"empty address": {args: []string{"--sa-address", ""}, want: `--sa-address: invalid value ""` + address},
		"empty port":    {args: []string{"--sa-port", ""}, want: `--sa-port: invalid value ""` + port},
		"long port":     {args: []string{"--sa-port", "003005"}, want: `--sa-port: invalid value "003005"` + port},
		"long address port": {
			args: []string{"--sa-address", "h:003005"}, want: `--sa-address: invalid value "h:003005"` + address,
		},
		"empty port, equals": {args: []string{"--sa-port="}, want: `--sa-port: invalid value ""` + port},
		"empty CA file": {
			args: []string{"--sa-ca-file", ""},
			want: `--sa-ca-file: invalid value "", expected a path to a CA certificate file`,
		},
		"empty C spelling CA file": {
			args: []string{"--sa-cafile="},
			want: `--sa-cafile: invalid value "", expected a path to a CA certificate file`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.EqualError(t, parseSecretAgentFlags(t, tt.args, nil).Validate(), tt.want)
		})
	}

	for _, args := range [][]string{{"--sa-port", "03005"}, {"--sa-address", "h:03005"}} {
		require.NoError(t, parseSecretAgentFlags(t, args, nil).Validate(), args)
	}
}

func TestSecretAgentFlagUsage(t *testing.T) {
	t.Parallel()

	fs := NewDefaultSecretAgentFlags().NewFlagSet(DefaultWrapHelpString)
	normalize := func(text string) string {
		return strings.Join(strings.Fields(strings.NewReplacer(`"`, "", "'", "").Replace(text)), " ")
	}

	tests := map[string]struct {
		usage string
		def   string
	}{
		"sa-address": {
			usage: `"<host>[:<port>]" or "[<ipv6>][:<port>]". Secret Agent hostname or IP address.`,
			def:   "127.0.0.1:3005",
		},
		"sa-port": {usage: "Secret Agent port, 1 to 65535. Overrides a port in --sa-address.", def: "3005"},
		"sa-timeout": {
			usage: "Timeout in milliseconds for Secret Agent requests, an integer from 1 to 2147483647.",
			def:   "1000",
		},
		"sa-ca-file": {
			usage: "Path to a CA certificate file. Enables TLS to the Secret Agent and verifies its certificate" +
				" against this CA. The agent's hostname or IP address must be in the certificate.",
			def: "none",
		},
	}

	for name, tt := range tests {
		one := pflag.NewFlagSet(name, pflag.ContinueOnError)
		one.AddFlag(fs.Lookup(name))
		help := normalize(one.FlagUsages())

		usage := normalize(fs.Lookup(name).Usage)
		usage = strings.TrimSuffix(strings.TrimSuffix(usage, " Default: "+tt.def), " (default "+tt.def+")")

		require.Equal(t, normalize(tt.usage), usage, name)

		if tt.def != "none" {
			require.Equal(t, 1, strings.Count(help, tt.def), help)
			require.True(t, strings.Contains(help, "Default: "+tt.def) || strings.Contains(help, "(default "+tt.def+")"), help)
		}
	}

	require.NotContains(t, fs.FlagUsages(), "sa-cafile")
}

func TestSecretAgentCAFileBeatsCSpelling(t *testing.T) {
	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"user": encode(resolvedUser)}})
	other := secretagenttest.NewTLSServer(t, nil)
	missing := filepath.Join(t.TempDir(), "missing.pem")

	for name, args := range map[string][]string{
		"C spelling first": {"--sa-cafile", missing, "--sa-ca-file", agent.CAFile()},
		"C spelling last":  {"--sa-ca-file", agent.CAFile(), "--sa-cafile", missing},
	} {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolFlags(t, append(args, "-U", "secrets:aql:user", "--sa-address", agent.Addr())...)

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, resolvedUser, af.User)
		})
	}

	for name, conf := range map[string]string{
		"C spelling first": "sa-cafile = %[2]q\nsa-ca-file = %[1]q\n",
		"C spelling last":  "sa-ca-file = %[1]q\nsa-cafile = %[2]q\n",
	} {
		t.Run("config "+name, func(t *testing.T) {
			af, sa := parseToolConfig(t, fmt.Sprintf(
				"[cluster]\nuser = \"secrets:aql:user\"\n\n[secret-agent]\nsa-address = %q\n", agent.Addr())+
				fmt.Sprintf(conf, agent.CAFile(), other.CAFile()))

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, resolvedUser, af.User)
		})
	}
}

func TestSecretAgentInstanceSectionReplacesDefault(t *testing.T) {
	agent := newTestAgent(t)

	conf := fmt.Sprintf("[secret-agent]\nsa-port = \"1\"\nsa-timeout = 1\n\n[secret-agent_x]\nsa-address = %q\n",
		agent.Addr())

	af, sa := parseToolConfigArgs(t, conf, "x", "-U", "secrets:aql:user")
	require.NoError(t, af.ResolveSecrets(t.Context(), sa))
	require.Equal(t, resolvedUser, af.User)

	_, sa = parseToolConfigArgs(t, conf, "y")

	address, err := sa.address()
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:1", address)
}

func TestSecretAgentIPv6Address(t *testing.T) {
	agent := newTestAgent(t)
	addr, _ := newProxy(t, "[::1]:0", agent.Addr())

	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	for _, args := range [][]string{
		{"--sa-address", addr},
		{"--sa-address", "::1", "--sa-port", port},
		{"--sa-address", "[::1]", "--sa-port", port},
	} {
		af, sa := parseToolFlags(t, append(args, "-U", "secrets:aql:user")...)
		require.NoError(t, af.ResolveSecrets(t.Context(), sa), args)
		require.Equal(t, resolvedUser, af.User)
	}

	for _, conf := range []string{
		fmt.Sprintf("sa-address = %q\n", addr),
		fmt.Sprintf("sa-address = \"::1\"\nsa-port = %q\n", port),
	} {
		af, sa := parseToolConfig(t, "[cluster]\nuser = \"secrets:aql:user\"\n\n[secret-agent]\n"+conf)
		require.NoError(t, af.ResolveSecrets(t.Context(), sa), conf)
		require.Equal(t, resolvedUser, af.User)
	}
}

func TestSecretAgentTLSVerifiesCAAndHost(t *testing.T) {
	t.Parallel()

	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"user": encode(resolvedUser)}})
	other := secretagenttest.NewTLSServer(t, nil)

	_, port, err := net.SplitHostPort(agent.Addr())
	require.NoError(t, err)

	resolve := func(t *testing.T, address, caFile string) error {
		t.Helper()

		af, sa := parseToolFlags(t, "-U", "secrets:aql:user", "--sa-address", address, "--sa-ca-file", caFile)

		return af.ResolveSecrets(t.Context(), sa)
	}

	t.Run("IP address", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, resolve(t, agent.Addr(), agent.CAFile()))
	})

	t.Run("host name", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, resolve(t, "localhost:"+port, agent.CAFile()))
	})

	t.Run("other CA", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, resolve(t, agent.Addr(), other.CAFile()), secretagent.ErrRequestFailed)
	})

	t.Run("address not in the certificate", func(t *testing.T) {
		addr, _ := newProxy(t, "[::1]:0", agent.Addr())

		err := resolve(t, addr, agent.CAFile())
		require.ErrorIs(t, err, secretagent.ErrRequestFailed)
		require.ErrorContains(t, err, "certificate")
	})
}

func TestSecretAgentCAFileReadOnlyWhenFetching(t *testing.T) {
	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"user": encode(resolvedUser)}})
	addr, conns := newProxy(t, "127.0.0.1:0", agent.Addr())
	missing := filepath.Join(t.TempDir(), "missing.pem")
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600))

	t.Run("not read without a secret", func(t *testing.T) {
		for _, conf := range []string{"sa-ca-file = %q\n", "sa-cafile = %q\n"} {
			require.NoError(t, resolveToolConfig(t, fmt.Sprintf("[secret-agent]\n"+conf, missing), ""), conf)
		}

		require.NoError(t, resolveToolConfig(t, "", "", "--sa-ca-file", missing))
	})

	for _, option := range []string{"--sa-ca-file", "--sa-cafile"} {
		t.Run(option+" beats a config file CA file that cannot be read", func(t *testing.T) {
			af, sa := parseToolConfigArgs(t, fmt.Sprintf(
				"[cluster]\nuser = \"secrets:aql:user\"\n\n[secret-agent]\nsa-address = %q\nsa-ca-file = %q\n",
				agent.Addr(), missing), "", option, agent.CAFile())

			require.NoError(t, af.ResolveSecrets(t.Context(), sa))
			require.Equal(t, resolvedUser, af.User)
		})
	}

	tests := map[string]struct {
		conf     string
		instance string
		want     string
		args     []string
	}{
		"--sa-ca-file": {
			args: []string{"--sa-ca-file", missing}, want: `--sa-ca-file: cannot load CA file "` + missing + `": no such file or directory`,
		},
		"--sa-cafile": {args: []string{"--sa-cafile", notPEM}, want: `--sa-cafile: cannot load CA file "` + notPEM + `": no certificates found`},
		"sa-ca-file": {
			conf: fmt.Sprintf("[secret-agent]\nsa-ca-file = %q\n", missing),
			want: `sa-ca-file in the [secret-agent] config section: cannot load CA file "` + missing + `": no such file or directory`,
		},
		"sa-cafile": {
			conf: fmt.Sprintf("[secret-agent]\nsa-cafile = %q\n", notPEM),
			want: `sa-cafile in the [secret-agent] config section: cannot load CA file "` + notPEM + `": no certificates found`,
		},
		"instance sa-ca-file": {
			conf:     fmt.Sprintf("[secret-agent]\nsa-ca-file = %q\n\n[secret-agent_x]\nsa-ca-file = %q\n", notPEM, missing),
			instance: "x",
			want:     `sa-ca-file in the [secret-agent_x] config section: cannot load CA file "` + missing + `": no such file or directory`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := conns.Load()

			err := resolveToolConfig(t, tt.conf, tt.instance,
				append([]string{"--sa-address", addr, "-U", "secrets:aql:user"}, tt.args...)...)

			require.EqualError(t, err, tt.want)
			require.ErrorIs(t, err, secretagent.ErrInvalidConfig)
			require.Equal(t, before, conns.Load())
		})
	}
}

func TestSecretAgentOnlySelectedSectionIsRead(t *testing.T) {
	const invalid = "sa-port = 0\nsa-timeout = \"x\"\nsa-ca-file = \"\"\nbogus = 1\n"

	tests := map[string]struct {
		conf     string
		instance string
		want     string
	}{
		"instance section, invalid default section": {
			conf:     "[secret-agent]\n" + invalid + "\n[secret-agent_x]\nsa-address = \"h:4100\"\n",
			instance: "x", want: "h:4100",
		},
		"empty instance section, invalid default section": {
			conf: "[secret-agent]\n" + invalid + "\n[secret-agent_x]\n", instance: "x", want: "127.0.0.1:3005",
		},
		"no instance, invalid instance section": {
			conf: "[secret-agent]\nsa-address = \"h:4100\"\n\n[secret-agent_x]\n" + invalid, want: "h:4100",
		},
		"other instance, invalid instance section": {
			conf:     "[secret-agent]\nsa-address = \"h:4100\"\n\n[secret-agent_x]\n" + invalid,
			instance: "y", want: "h:4100",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			af, sa := parseToolConfigArgs(t, tt.conf, tt.instance)
			require.NoError(t, af.ResolveSecrets(t.Context(), sa))

			address, err := sa.address()
			require.NoError(t, err)
			require.Equal(t, tt.want, address)
		})
	}
}

func TestSecretAgentConfigKeysIgnoreCase(t *testing.T) {
	_, sa := parseToolConfig(t, "[secret-agent]\nSA-Address = \"h:4100\"\nSa-Timeout = 250\n")

	address, err := sa.address()
	require.NoError(t, err)
	require.Equal(t, "h:4100", address)
	require.Equal(t, 250, sa.Timeout)

	_, _, err = loadToolConfig(t, "[secret-agent]\nSA-PORT = 0\n", "")
	require.ErrorContains(t, err, `invalid value "0" for `)
	require.ErrorContains(t, err, " in the [secret-agent] config section, expected an integer from 1 to 65535")
}

func resolveToolConfigFiles(t *testing.T, home, user, instance string, args ...string) (*AerospikeFlags, error) {
	t.Helper()

	af, sa, err := loadToolConfigFiles(t, home, user, instance, args...)
	if err == nil {
		err = af.ResolveSecrets(t.Context(), sa)
	}

	return af, err
}

func TestSecretAgentConfigFilesMergeKeyByKey(t *testing.T) {
	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"user": encode(resolvedUser)}})

	af, err := resolveToolConfigFiles(t,
		fmt.Sprintf("[cluster_x]\nuser = \"secrets:aql:user\"\n\n[secret-agent_x]\nsa-address = \"127.0.0.1:1\"\n"+
			"sa-ca-file = %q\n", agent.CAFile()),
		fmt.Sprintf("[secret-agent]\nsa-address = %q\n", agent.Addr()), "x")

	require.NoError(t, err)
	require.Equal(t, resolvedUser, af.User)
}

func TestSecretAgentConfigFilesAddressAndPort(t *testing.T) {
	tests := map[string]struct {
		home string
		user string
		want string
		args []string
	}{
		"later address port beats earlier sa-port": {home: `sa-port = "4000"`, user: `sa-address = "h:4100"`, want: "h:4100"},
		"later sa-port beats earlier address port": {home: `sa-address = "h:4100"`, user: `sa-port = "4200"`, want: "h:4200"},
		"later address without a port keeps the earlier address port": {
			home: `sa-address = "h:4100"`, user: `sa-address = "h2"`, want: "h2:4100",
		},
		"later address without a port keeps the earlier sa-port": {
			home: "sa-address = \"h:4100\"\nsa-port = \"4200\"", user: `sa-address = "h2"`, want: "h2:4200",
		},
		"sa-port beats the address port in the same file": {
			user: "sa-address = \"h:4100\"\nsa-port = \"4200\"", want: "h:4200",
		},
		"command line beats both files": {
			home: `sa-address = "h:4100"`, user: `sa-port = "4200"`, args: []string{"--sa-address", "h3:4300"},
			want: "h3:4300",
		},
		"command line host keeps the port of the files": {
			home: `sa-port = "4200"`, user: `sa-address = "h:4100"`, args: []string{"--sa-address", "h3"},
			want: "h3:4100",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, sa, err := loadToolConfigFiles(t, "[secret-agent]\n"+tt.home+"\n", "[secret-agent]\n"+tt.user+"\n", "",
				tt.args...)
			require.NoError(t, err)

			address, err := sa.address()
			require.NoError(t, err)
			require.Equal(t, tt.want, address)
		})
	}
}

func TestSecretAgentConfigFilesCAFile(t *testing.T) {
	agent := secretagenttest.NewTLSServer(t, secretagenttest.Secrets{"aql": {"user": encode(resolvedUser)}})
	missing := filepath.Join(t.TempDir(), "missing.pem")

	tests := map[string]struct {
		home     string
		user     string
		instance string
		want     string
	}{
		"later sa-cafile beats earlier sa-ca-file": {
			home: fmt.Sprintf("[secret-agent]\nsa-address = %q\nsa-ca-file = %q\n", agent.Addr(), missing),
			user: fmt.Sprintf("[secret-agent]\nsa-cafile = %q\n", agent.CAFile()),
		},
		"later sa-ca-file beats earlier sa-cafile": {
			home: fmt.Sprintf("[secret-agent]\nsa-address = %q\nsa-cafile = %q\n", agent.Addr(), missing),
			user: fmt.Sprintf("[secret-agent]\nsa-ca-file = %q\n", agent.CAFile()),
		},
		"sa-ca-file beats sa-cafile in the same file": {
			home: fmt.Sprintf("[secret-agent]\nsa-address = %q\n", agent.Addr()),
			user: fmt.Sprintf("[secret-agent]\nsa-ca-file = %q\nsa-cafile = %q\n", agent.CAFile(), missing),
		},
		"earlier instance section names the CA file": {
			home:     fmt.Sprintf("[secret-agent_x]\nsa-address = \"127.0.0.1:1\"\nsa-ca-file = %q\n", missing),
			user:     fmt.Sprintf("[secret-agent]\nsa-address = %q\n", agent.Addr()),
			instance: "x",
			want:     `sa-ca-file in the [secret-agent_x] config section: cannot load CA file "` + missing + `": no such file or directory`,
		},
		"later instance section names the CA file": {
			home:     fmt.Sprintf("[secret-agent]\nsa-address = %q\nsa-ca-file = %q\n", agent.Addr(), agent.CAFile()),
			user:     fmt.Sprintf("[secret-agent_x]\nsa-cafile = %q\n", missing),
			instance: "x",
			want:     `sa-cafile in the [secret-agent_x] config section: cannot load CA file "` + missing + `": no such file or directory`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cluster := "[cluster]\n"
			if tt.instance != "" {
				cluster = "[cluster_" + tt.instance + "]\n"
			}

			af, err := resolveToolConfigFiles(t, cluster+"user = \"secrets:aql:user\"\n\n"+tt.home, tt.user, tt.instance)

			if tt.want != "" {
				require.EqualError(t, err, tt.want)
				return
			}

			require.NoError(t, err)
			require.Equal(t, resolvedUser, af.User)
		})
	}
}

func TestSecretAgentConfigFilesCheckedPerFile(t *testing.T) {
	// Errors name the file, since up to three files are read.
	tests := map[string]struct {
		home     string
		user     string
		instance string
		file     string
		want     string
	}{
		"invalid value in an earlier file": {
			home: "[secret-agent]\nsa-port = 0\n",
			user: "[secret-agent]\nsa-port = \"3005\"\n",
			file: "astools-flags-test.conf",
			want: `invalid value "0" for sa-port in the [secret-agent] config section, expected an integer from 1 to 65535`,
		},
		"unknown key in an earlier file": {
			home: "[secret-agent]\nbogus = 1\n",
			user: "[secret-agent]\nsa-port = \"3005\"\n",
			file: "astools-flags-test.conf",
			want: "unknown key bogus in the [secret-agent] config section",
		},
		"invalid value in a later instance section": {
			home:     "[secret-agent]\nsa-port = \"3005\"\n",
			user:     "[secret-agent_x]\nsa-timeout = 0\n",
			instance: "x",
			file:     "user.conf",
			want: `invalid value "0" for sa-timeout in the [secret-agent_x] config section,` +
				" expected an integer from 1 to 2147483647",
		},
		"unselected sections in each file are ignored": {
			home:     "[secret-agent]\nsa-port = 0\n\n[secret-agent_x]\nsa-port = \"3005\"\n",
			user:     "[secret-agent_y]\nbogus = 1\n",
			instance: "x",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := loadToolConfigFiles(t, tt.home, tt.user, tt.instance)

			if tt.want == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.Regexp(t, `^config file \S*/`+regexp.QuoteMeta(tt.file)+`: `+regexp.QuoteMeta(tt.want)+`$`,
				err.Error())
		})
	}
}

func TestSecretAgentInstanceSectionsMergePerFile(t *testing.T) {
	// As in the C tools, a later file's sa-address port beats an earlier file's
	// sa-port, in instance sections too.
	_, sa, err := loadToolConfigFiles(t, "[secret-agent_x]\nsa-port = \"4000\"\n",
		"[secret-agent_x]\nsa-address = \"agent:5000\"\n", "x")
	require.NoError(t, err)

	address, err := sa.address()
	require.NoError(t, err)
	require.Equal(t, "agent:5000", address)
}

func TestSecretAgentEmptyTimeout(t *testing.T) {
	t.Parallel()

	err := parseSecretAgentFlags(t, []string{"--sa-timeout", ""}, nil).Validate()
	require.EqualError(t, err, `--sa-timeout: invalid value "", expected an integer from 1 to 2147483647`)
}
