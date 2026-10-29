package flags

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/spf13/pflag"
)

const defaultSecretAgentTimeoutMs = 1000

var secretAgentExpected = map[string]string{
	"sa-address": "<host>[:<port>] or [<ipv6>][:<port>]",
	"sa-port":    "an integer from 1 to 65535",
	"sa-timeout": fmt.Sprintf("an integer from 1 to %d", math.MaxInt32),
	"sa-ca-file": "a path to a CA certificate file",
	"sa-cafile":  "a path to a CA certificate file",
}

// SecretAgentFlags defines the storage backing for the Aerospike Secret Agent
// flags returned by NewFlagSet. They match the --sa-* options of the Aerospike
// C tools and are read from the [secret-agent] config section.
type SecretAgentFlags struct {
	flagSet         *pflag.FlagSet
	Address         string `mapstructure:"sa-address"`
	Port            string `mapstructure:"sa-port"`
	CAFile          string `mapstructure:"sa-ca-file"`
	legacyCAFile    string
	timeout         string
	section         string
	confAddressPort string
	Timeout         int `mapstructure:"sa-timeout"`
}

func NewDefaultSecretAgentFlags() *SecretAgentFlags {
	return &SecretAgentFlags{Timeout: defaultSecretAgentTimeoutMs}
}

// NewFlagSet returns a new pflag.FlagSet with the Secret Agent flags defined.
// Values set in the returned FlagSet will be stored in the SecretAgentFlags.
// Command line values are checked when the agent is used, and config file
// values when the config file is loaded.
func (sf *SecretAgentFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}
	f.Var(sf.value("sa-address", &sf.Address), "sa-address", fmtUsage(`"<host>[:<port>]" or "[<ipv6>][:<port>]".`+
		" Secret Agent hostname or IP address. (default 127.0.0.1:3005)"))
	f.Var(sf.value("sa-port", &sf.Port), "sa-port", fmtUsage("Secret Agent port, 1 to 65535."+
		" Overrides a port in --sa-address. (default 3005)"))
	f.Var(sf.value("sa-timeout", &sf.timeout), "sa-timeout", fmtUsage("Timeout in milliseconds for Secret Agent"+
		" requests, an integer from 1 to 2147483647."))
	f.Var(sf.value("sa-ca-file", &sf.CAFile), "sa-ca-file", fmtUsage("Path to a CA certificate file. Enables TLS"+
		" to the Secret Agent and verifies its certificate against this CA. The agent's hostname or IP address"+
		" must be in the certificate. (default none)"))
	f.Var(sf.value("sa-cafile", &sf.legacyCAFile), "sa-cafile", fmtUsage("Same as --sa-ca-file."))
	_ = f.MarkHidden("sa-cafile")

	sf.flagSet = f

	return f
}

// Validate checks the address, port and timeout without contacting the agent.
func (sf *SecretAgentFlags) Validate() error {
	_, err := sf.config()

	return err
}

// NewClient returns a Secret Agent client for the flags. Secret values are
// base64-decoded, as in the Aerospike C tools.
func (sf *SecretAgentFlags) NewClient() (*secretagent.Client, error) {
	cfg, err := sf.config()
	if err != nil {
		return nil, err
	}

	if cfg.TLS, err = secretagent.NewTLSConfig(secretagent.TLSOptions{CAFile: sf.caFile()}); err != nil {
		return nil, fmt.Errorf("%s: %w", sf.label(sf.caFileOption()), err)
	}

	return secretagent.NewClient(cfg)
}

// caFileOption picks --sa-ca-file or --sa-cafile, the C tools' spelling that a
// config file shared with them must use: the command line beats the config
// file, and --sa-ca-file beats --sa-cafile from the same source.
func (sf *SecretAgentFlags) caFileOption() string {
	if sf.changed("sa-ca-file") || (!sf.changed("sa-cafile") && sf.CAFile != "") {
		return "sa-ca-file"
	}

	return "sa-cafile"
}

func (sf *SecretAgentFlags) caFile() string {
	if sf.caFileOption() == "sa-ca-file" {
		return sf.CAFile
	}

	return sf.legacyCAFile
}

func (sf *SecretAgentFlags) config() (secretagent.Config, error) {
	address, err := sf.address()
	if err != nil {
		return secretagent.Config{}, err
	}

	timeout := sf.Timeout

	if sf.timeout != "" {
		var ok bool
		if timeout, ok = parseTimeout(sf.timeout); !ok {
			return secretagent.Config{}, fmt.Errorf("--sa-timeout: invalid value %s, expected %s",
				sf.timeout, secretAgentExpected["sa-timeout"])
		}
	} else if timeout < 1 || timeout > math.MaxInt32 {
		return secretagent.Config{}, fmt.Errorf("--sa-timeout: invalid value %d, expected %s",
			timeout, secretAgentExpected["sa-timeout"])
	}

	if option := sf.caFileOption(); sf.caFile() == "" && sf.changed(option) {
		return secretagent.Config{}, fmt.Errorf("--%s: invalid value , expected %s", option, secretAgentExpected[option])
	}

	return secretagent.Config{
		Address: address,
		Timeout: time.Duration(timeout) * time.Millisecond,
		Base64:  true,
	}, nil
}

// address merges --sa-address and --sa-port like the C tools: an explicit port
// beats a port in the address from the same source, and the command line beats
// the config file key by key, so a command line host keeps a config file port.
func (sf *SecretAgentFlags) address() (string, error) {
	host, port := secretagent.DefaultHost, ""

	if sf.Address != "" || sf.changed("sa-address") {
		var ok bool
		if host, port, ok = parseSecretAgentAddress(sf.Address); !ok {
			return "", fmt.Errorf("--sa-address: invalid value %s, expected %s", sf.Address, secretAgentExpected["sa-address"])
		}
	}

	if sf.Port != "" || sf.changed("sa-port") {
		if !validPort(sf.Port) {
			return "", fmt.Errorf("--sa-port: invalid value %s, expected %s", sf.Port, secretAgentExpected["sa-port"])
		}

		addressWins := port != "" && sf.changed("sa-address") && !sf.changed("sa-port")
		if !addressWins {
			port = sf.Port
		}
	}

	if port == "" {
		port = sf.confAddressPort
	}

	if port == "" {
		port = strconv.Itoa(secretagent.DefaultPort)
	}

	return net.JoinHostPort(host, port), nil
}

func (sf *SecretAgentFlags) changed(name string) bool {
	if sf.flagSet == nil {
		return false
	}

	return sf.flagSet.Changed(name)
}

func (sf *SecretAgentFlags) label(name string) string {
	if sf.section == "" || sf.changed(name) {
		return "--" + name
	}

	return configLabel(name, sf.section)
}

func configLabel(name, section string) string {
	return fmt.Sprintf("%s in the [%s] config section", name, section)
}

func (sf *SecretAgentFlags) value(name string, value *string) *secretAgentValue {
	return &secretAgentValue{sf: sf, value: value, name: name}
}

type secretAgentValue struct {
	sf    *SecretAgentFlags
	value *string
	name  string
}

func (v *secretAgentValue) String() string {
	if v.name == "sa-timeout" && *v.value == "" {
		return strconv.Itoa(v.sf.Timeout)
	}

	return *v.value
}

func (v *secretAgentValue) Type() string {
	if v.name == "sa-timeout" {
		return "int"
	}

	return "string"
}

func (v *secretAgentValue) Set(value string) error {
	if v.name == "sa-cafile" {
		fmt.Fprintln(os.Stderr, "Warning: Argument --sa-cafile is deprecated. Use --sa-ca-file instead.")
	}

	v.set(value)

	return nil
}

func (v *secretAgentValue) set(value string) {
	*v.value = value

	if timeout, ok := parseTimeout(value); ok && v.name == "sa-timeout" {
		v.sf.Timeout = timeout
	}
}

// SetConfig is called by config.SetFlags with the config file value as read.
func (v *secretAgentValue) SetConfig(section string, value any) error {
	text, ok := configText(value, v.name == "sa-port" || v.name == "sa-timeout")
	if !ok || !v.valid(text) {
		return fmt.Errorf("invalid value %v for %s, expected %s", value, configLabel(v.name, section),
			secretAgentExpected[v.name])
	}

	if v.name == "sa-ca-file" || v.name == "sa-cafile" {
		if _, err := secretagent.NewTLSConfig(secretagent.TLSOptions{CAFile: text}); err != nil {
			return fmt.Errorf("%s: %w", configLabel(v.name, section), err)
		}
	}

	if v.name == "sa-address" {
		_, v.sf.confAddressPort, _ = parseSecretAgentAddress(text)
	}

	v.sf.section = section

	if !v.sf.changed(v.name) {
		v.set(text)
	}

	return nil
}

func (v *secretAgentValue) valid(text string) bool {
	switch v.name {
	case "sa-address":
		_, _, ok := parseSecretAgentAddress(text)
		return ok
	case "sa-port":
		return validPort(text)
	case "sa-timeout":
		_, ok := parseTimeout(text)
		return ok
	}

	return text != ""
}

func configText(value any, number bool) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case int:
		return strconv.Itoa(v), number
	case int64:
		return strconv.FormatInt(v, 10), number
	}

	return "", false
}

// parseSecretAgentAddress accepts <host>[:<port>] and [<ipv6>][:<port>]. An
// unbracketed host with more than one colon must be an IPv6 address.
func parseSecretAgentAddress(address string) (host, port string, ok bool) {
	if strings.ContainsFunc(address, unicode.IsSpace) {
		return "", "", false
	}

	hasPort := false

	if rest, found := strings.CutPrefix(address, "["); found {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", "", false
		}

		host = rest[:end]

		if after := rest[end+1:]; after != "" {
			if port, hasPort = strings.CutPrefix(after, ":"); !hasPort {
				return "", "", false
			}
		}

		if !isIPv6(host) {
			return "", "", false
		}
	} else if strings.Count(address, ":") == 1 {
		host, port, hasPort = strings.Cut(address, ":")
	} else {
		host = address
		if strings.Contains(host, ":") && !isIPv6(host) {
			return "", "", false
		}
	}

	if host == "" || (hasPort && !validPort(port)) {
		return "", "", false
	}

	return host, port, true
}

func isIPv6(host string) bool {
	addr, zone, hasZone := strings.Cut(host, "%")
	if hasZone && zone == "" {
		return false
	}

	ip := net.ParseIP(addr)

	return ip != nil && ip.To4() == nil
}

func validPort(port string) bool {
	if port == "" || len(port) > 5 || strings.TrimLeft(port, "0123456789") != "" {
		return false
	}

	n, err := strconv.Atoi(port)

	return err == nil && n >= 1 && n <= math.MaxUint16
}

// parseTimeout accepts decimal digits only, so 010 is 10 as in the C tools.
func parseTimeout(timeout string) (int, bool) {
	if timeout == "" || strings.TrimLeft(timeout, "0123456789") != "" {
		return 0, false
	}

	n, err := strconv.Atoi(timeout)
	if err != nil || n < 1 || n > math.MaxInt32 {
		return 0, false
	}

	return n, true
}
