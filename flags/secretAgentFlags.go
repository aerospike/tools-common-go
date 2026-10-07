package flags

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aerospike/tools-common-go/secretagent"
	"github.com/spf13/pflag"
)

const defaultSecretAgentTimeoutMs = 1000

// SecretAgentFlags defines the storage backing for the Aerospike Secret Agent
// flags returned by NewFlagSet. They match the --sa-* options of the Aerospike
// C tools and are read from the [secret-agent] config section.
type SecretAgentFlags struct {
	flagSet *pflag.FlagSet
	Address string `mapstructure:"sa-address"`
	Port    string `mapstructure:"sa-port"`
	CAFile  string `mapstructure:"sa-cafile"`
	Timeout int    `mapstructure:"sa-timeout"`
}

func NewDefaultSecretAgentFlags() *SecretAgentFlags {
	return &SecretAgentFlags{Timeout: defaultSecretAgentTimeoutMs}
}

// NewFlagSet returns a new pflag.FlagSet with the Secret Agent flags defined.
// Values set in the returned FlagSet will be stored in the SecretAgentFlags.
func (sf *SecretAgentFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}
	f.StringVar(&sf.Address, "sa-address", "", fmtUsage("The Aerospike Secret Agent used for"+
		" secrets:<resource>:<key> values, as <host>[:<port>] or [<ipv6>][:<port>]. (default 127.0.0.1:3005)"))
	f.StringVar(&sf.Port, "sa-port", "", fmtUsage("The Secret Agent `port`. Overrides a port in --sa-address."+
		" (default 3005)"))
	f.IntVar(&sf.Timeout, "sa-timeout", defaultSecretAgentTimeoutMs, fmtUsage("The Secret Agent timeout in"+
		" milliseconds, 1 or more. It covers the name lookup, the connection, the TLS handshake and the request."))
	f.StringVar(&sf.CAFile, "sa-cafile", "", fmtUsage("A CA certificate file. Enables TLS to the Secret Agent"+
		" and verifies its certificate against this CA."))

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

	if cfg.TLS, err = secretagent.NewTLSConfig(secretagent.TLSOptions{CAFile: sf.CAFile}); err != nil {
		return nil, fmt.Errorf("--sa-cafile: %w", err)
	}

	return secretagent.NewClient(cfg)
}

func (sf *SecretAgentFlags) config() (secretagent.Config, error) {
	address, err := sf.address()
	if err != nil {
		return secretagent.Config{}, err
	}

	if sf.Timeout < 1 {
		return secretagent.Config{}, fmt.Errorf("--sa-timeout: invalid value %d, expected an integer from 1 to %d",
			sf.Timeout, math.MaxInt32)
	}

	return secretagent.Config{
		Address: address,
		Timeout: time.Duration(sf.Timeout) * time.Millisecond,
		Base64:  true,
	}, nil
}

// address merges --sa-address and --sa-port like the C tools: an explicit port
// beats a port in the address from the same source, and the command line beats
// the config file.
func (sf *SecretAgentFlags) address() (string, error) {
	host, port := secretagent.DefaultHost, ""

	if sf.Address != "" {
		var ok bool
		if host, port, ok = parseSecretAgentAddress(sf.Address); !ok {
			return "", fmt.Errorf("--sa-address: invalid value %s", sf.Address)
		}
	}

	if sf.Port != "" {
		if !validPort(sf.Port) {
			return "", fmt.Errorf("--sa-port: invalid value %s", sf.Port)
		}

		addressWins := port != "" && sf.changed("sa-address") && !sf.changed("sa-port")
		if !addressWins {
			port = sf.Port
		}
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

// parseSecretAgentAddress accepts <host>[:<port>] and [<ipv6>][:<port>]. An
// unbracketed host with more than one colon must be an IPv6 address.
func parseSecretAgentAddress(address string) (host, port string, ok bool) {
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
	if port == "" || strings.TrimLeft(port, "0123456789") != "" {
		return false
	}

	n, err := strconv.Atoi(port)

	return err == nil && n >= 1 && n <= math.MaxUint16
}
