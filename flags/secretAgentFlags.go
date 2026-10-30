package flags

import (
	"errors"
	"fmt"
	"io/fs"
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

const (
	saAddress      = "sa-address"
	saPort         = "sa-port"
	saTimeout      = "sa-timeout"
	saCAFile       = "sa-ca-file"
	saLegacyCAFile = "sa-cafile"
)

var secretAgentExpected = map[string]string{
	saAddress:      "<host>[:<port>] or [<ipv6>][:<port>]",
	saPort:         "an integer from 1 to 65535",
	saTimeout:      fmt.Sprintf("an integer from 1 to %d", math.MaxInt32),
	saCAFile:       "a path to a CA certificate file",
	saLegacyCAFile: "a path to a CA certificate file",
}

// SecretAgentFlags defines the storage backing for the Aerospike Secret Agent
// flags returned by NewFlagSet. They match the --sa-* options of the Aerospike
// C tools and are read from the [secret-agent] config section.
type SecretAgentFlags struct {
	flagSet         *pflag.FlagSet
	configFile      map[string]int
	Address         string `mapstructure:"sa-address"`
	Port            string `mapstructure:"sa-port"`
	CAFile          string `mapstructure:"sa-ca-file"`
	legacyCAFile    string
	timeout         string
	section         string
	confAddressPort string
	Timeout         int `mapstructure:"sa-timeout"`
	file            int
}

func NewDefaultSecretAgentFlags() *SecretAgentFlags {
	return &SecretAgentFlags{Timeout: defaultSecretAgentTimeoutMs}
}

// NewFlagSet returns a new pflag.FlagSet with the Secret Agent flags defined.
// Values set in the returned FlagSet will be stored in the SecretAgentFlags.
// Command line values are checked by Validate and ResolveSecrets, and config
// file values when the config file is loaded. The CA file is read only when a
// secret is fetched.
func (sf *SecretAgentFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}
	f.Var(sf.value(saAddress, &sf.Address), saAddress, fmtUsage(`"<host>[:<port>]" or "[<ipv6>][:<port>]".`+
		" Secret Agent hostname or IP address. (default 127.0.0.1:3005)"))
	f.Var(sf.value(saPort, &sf.Port), saPort, fmtUsage("Secret Agent port, 1 to 65535."+
		" Overrides a port in --sa-address. (default 3005)"))
	f.Var(sf.value(saTimeout, &sf.timeout), saTimeout, fmtUsage("Timeout in milliseconds for Secret Agent"+
		" requests, an integer from 1 to 2147483647."))
	f.Var(sf.value(saCAFile, &sf.CAFile), saCAFile, fmtUsage("Path to a CA certificate file. Enables TLS"+
		" to the Secret Agent and verifies its certificate against this CA. The agent's hostname or IP address"+
		" must be in the certificate. (default none)"))
	f.Var(sf.value(saLegacyCAFile, &sf.legacyCAFile), saLegacyCAFile, fmtUsage("Same as --sa-ca-file."))
	_ = f.MarkHidden(saLegacyCAFile)

	sf.flagSet = f

	return f
}

// Validate checks the flags without reading the CA file or contacting the agent.
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
		return nil, &caFileError{err: err, label: sf.label(sf.caFileOption()), path: sf.caFile()}
	}

	return secretagent.NewClient(cfg)
}

type caFileError struct {
	err   error
	label string
	path  string
}

func (e *caFileError) Error() string {
	reason := "no certificates found"

	var pathErr *fs.PathError
	if errors.As(e.err, &pathErr) {
		reason = pathErr.Err.Error()
	}

	return e.label + `: cannot load CA file "` + e.path + `": ` + reason
}

func (e *caFileError) Unwrap() error {
	return e.err
}

// caFileOption picks --sa-ca-file or --sa-cafile, the C tools' spelling that a
// config file shared with them must use: the command line beats the config
// file, and --sa-ca-file beats --sa-cafile from the same source.
func (sf *SecretAgentFlags) caFileOption() string {
	if sf.changed(saCAFile) || (!sf.changed(saLegacyCAFile) && sf.CAFile != "") {
		return saCAFile
	}

	return saLegacyCAFile
}

func (sf *SecretAgentFlags) caFile() string {
	if sf.caFileOption() == saCAFile {
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

	if sf.timeout != "" || sf.changed(saTimeout) {
		var ok bool
		if timeout, ok = parseTimeout(sf.timeout); !ok {
			return secretagent.Config{}, invalidOption(saTimeout, sf.timeout)
		}
	} else if timeout < 1 || timeout > math.MaxInt32 {
		return secretagent.Config{}, invalidOption(saTimeout, strconv.Itoa(timeout))
	}

	if option := sf.caFileOption(); sf.caFile() == "" && sf.changed(option) {
		return secretagent.Config{}, invalidOption(option, "")
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

	if sf.Address != "" || sf.changed(saAddress) {
		var ok bool
		if host, port, ok = parseSecretAgentAddress(sf.Address); !ok {
			return "", invalidOption(saAddress, sf.Address)
		}
	}

	if sf.Port != "" || sf.changed(saPort) {
		if !validPort(sf.Port) {
			return "", invalidOption(saPort, sf.Port)
		}

		addressWins := port != "" && sf.changed(saAddress) && !sf.changed(saPort)
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

func invalidOption(name, value string) error {
	return fmt.Errorf(`--%s: invalid value "%s", expected %s`, name, value, secretAgentExpected[name])
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
	if v.name == saTimeout && *v.value == "" {
		return strconv.Itoa(v.sf.Timeout)
	}

	return *v.value
}

func (v *secretAgentValue) Type() string {
	if v.name == saTimeout {
		return "int"
	}

	return "string"
}

func (v *secretAgentValue) Set(value string) error {
	if v.name == saLegacyCAFile {
		fmt.Fprintln(os.Stderr, "Warning: Argument --sa-cafile is deprecated. Use --sa-ca-file instead.")
	}

	v.set(value)

	return nil
}

func (v *secretAgentValue) set(value string) {
	*v.value = value

	if timeout, ok := parseTimeout(value); ok && v.name == saTimeout {
		v.sf.Timeout = timeout
	}
}

// SetConfig is called by config.SetFlags with the config file value as read.
func (v *secretAgentValue) SetConfig(section string, value any) error {
	text, ok := configText(value, v.name == saPort || v.name == saTimeout)
	if !ok || !v.valid(text) {
		return fmt.Errorf(`invalid value "%s" for %s, expected %s`, configValueText(value),
			configLabel(v.name, section), secretAgentExpected[v.name])
	}

	switch v.name {
	case saAddress:
		if _, port, _ := parseSecretAgentAddress(text); port != "" {
			v.sf.confAddressPort = port
			v.sf.dropEarlierFile(saPort, &v.sf.Port)
		}
	case saLegacyCAFile:
		v.sf.dropEarlierFile(saCAFile, &v.sf.CAFile)
	}

	if v.name == saCAFile || v.name == saLegacyCAFile {
		v.sf.section = section
	}

	if !v.sf.changed(v.name) {
		v.set(text)

		if v.sf.configFile == nil {
			v.sf.configFile = map[string]int{}
		}

		v.sf.configFile[v.name] = v.sf.file
	}

	return nil
}

// SetConfigFile is called by config.InitConfigFiles before the SetConfig
// calls of each config file, with the position of that file.
func (v *secretAgentValue) SetConfigFile(index int) {
	v.sf.file = index
}

// dropEarlierFile clears a value an earlier config file set, so that, as in
// the C tools, a later file's sa-address port beats an earlier sa-port and its
// sa-cafile an earlier sa-ca-file.
func (sf *SecretAgentFlags) dropEarlierFile(name string, value *string) {
	if file, ok := sf.configFile[name]; ok && file < sf.file {
		*value = ""
	}
}

func (v *secretAgentValue) valid(text string) bool {
	switch v.name {
	case saAddress:
		_, _, ok := parseSecretAgentAddress(text)
		return ok
	case saPort:
		return validPort(text)
	case saTimeout:
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

// configValueText shows a config file value as written, so 1.0 does not read
// as the valid integer 1.
func configValueText(value any) string {
	f, ok := value.(float64)
	if !ok {
		return fmt.Sprint(value)
	}

	text := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(text, ".eEnN") {
		text += ".0"
	}

	return text
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
