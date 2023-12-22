package flags

import (
	"strings"

	as "github.com/aerospike/aerospike-client-go/v6"
	"github.com/spf13/pflag"
)

const (
	DefaultMaxLineLength = 65
)

// AerospikeConfig can be used with SetAerospikeConf to
// get the values from an AerospikeFlags structure into an easier to use state.
// AerospikeConfig is usually used to configure the Aerospike Go client.
type AerospikeConfig struct {
	Seeds                  HostTLSPortSlice
	User                   string
	Password               string
	AuthMode               as.AuthMode
	RootCA                 [][]byte
	Cert                   []byte
	Key                    []byte
	KeyPass                []byte
	TLSProtocolsMinVersion TLSProtocol
	TLSProtocolsMaxVersion TLSProtocol
	// TLSCipherSuites        []uint16 // TODO
}

func NewDefaultAerospikeConfig() *AerospikeConfig {
	return &AerospikeConfig{
		Seeds: HostTLSPortSlice{NewDefaultHostTLSPort()},
	}
}

// AerospikeFlags defines the storage backing
// for Aerospike pflags.FlagSet returned from SetAerospikeFlags.
type AerospikeFlags struct {
	Seeds          HostTLSPortSliceFlag
	DefaultPort    int
	User           string
	Password       PasswordFlag
	AuthMode       AuthModeFlag
	TLSEnable      bool
	TLSName        string
	TLSProtocols   TLSProtocolsFlag
	TLSRootCAFile  CertFlag
	TLSRootCAPath  CertPathFlag
	TLSCertFile    CertFlag
	TLSKeyFile     CertFlag
	TLSKeyFilePass PasswordFlag
	// tlsCipherSuites tlsCipherSuitesFlag
}

func NewDefaultAerospikeFlags() *AerospikeFlags {
	return &AerospikeFlags{
		Seeds:        NewHostTLSPortSliceFlag(),
		DefaultPort:  DefaultPort,
		TLSProtocols: NewDefaultTLSProtocolsFlag(),
	}
}

// SetAerospikeConf sets the values in aerospikeConf based on the values set in flags.
// This function is useful for using AerospikeFlags to configure the Aerospike Go client.
func SetAerospikeConf(aerospikeConf *AerospikeConfig, flags *AerospikeFlags) {
	aerospikeConf.Seeds = flags.Seeds.Seeds
	aerospikeConf.User = flags.User
	aerospikeConf.Password = string(flags.Password)
	aerospikeConf.AuthMode = as.AuthMode(flags.AuthMode)

	if flags.TLSEnable {
		aerospikeConf.Cert = flags.TLSCertFile
		aerospikeConf.Key = flags.TLSKeyFile
		aerospikeConf.KeyPass = flags.TLSKeyFilePass
		aerospikeConf.TLSProtocolsMinVersion = flags.TLSProtocols.min
		aerospikeConf.TLSProtocolsMaxVersion = flags.TLSProtocols.max

		aerospikeConf.RootCA = [][]byte{}

		if len(flags.TLSRootCAFile) != 0 {
			aerospikeConf.RootCA = append(aerospikeConf.RootCA, flags.TLSRootCAFile)
		}

		aerospikeConf.RootCA = append(aerospikeConf.RootCA, flags.TLSRootCAPath...)
	}

	for _, elem := range aerospikeConf.Seeds {
		if elem.Port == 0 {
			elem.Port = flags.DefaultPort
		}

		if elem.TLSName == "" && flags.TLSName != "" {
			elem.TLSName = flags.TLSName
		}
	}
}

// UsageFormatter provides a method for modifying the usage text of the
// flags returned by SetAerospikeFlags.
type UsageFormatter func(string) string

// SetAerospikeFlags returns a new pflag.FlagSet with Aerospike flags defined.
// Values set in the returned FlagSet will be stored in the AerospikeFlags argument.
func SetAerospikeFlags(af *AerospikeFlags, fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}
	f.VarP(&af.Seeds, "host", "h", fmtUsage("The Aerospike host."))
	f.IntVarP(&af.DefaultPort, "port", "p", 3000, fmtUsage("The default Aerospike port."))
	f.StringVarP(&af.User, "user", "U", "", fmtUsage("The Aerospike user to use to connect to the Aerospike cluster."))
	f.VarP(&af.Password, "password", "P", fmtUsage("The Aerospike password to use to connect to the Aerospike cluster."))
	f.Var(&af.AuthMode, "auth", fmtUsage("The authentication mode used by the Aerospike server."+
		" INTERNAL uses standard user/pass. EXTERNAL uses external methods (like LDAP)"+
		" which are configured on the server. EXTERNAL requires TLS. PKI allows TLS"+
		" authentication and authorization based on a certificate. No user name needs to be configured."))
	f.BoolVar(&af.TLSEnable, "tls-enable", false, fmtUsage("Enable TLS authentication with Aerospike."+
		" If false, other tls options are ignored.",
	))
	f.StringVar(&af.TLSName, "tls-name", "", fmtUsage("The server TLS context to use to"+
		" authenticate the connection to Aerospike.",
	))
	f.Var(&af.TLSRootCAFile, "tls-cafile", fmtUsage("The CA used when connecting to Aerospike."))
	f.Var(&af.TLSRootCAPath, "tls-capath", fmtUsage("A path containing CAs for connecting to Aerospike."))
	f.Var(&af.TLSCertFile, "tls-certfile", fmtUsage("The certificate file for mutual TLS authentication with Aerospike."))
	f.Var(&af.TLSKeyFile, "tls-keyfile", fmtUsage("The key file used for mutual TLS authentication with Aerospike."))
	f.Var(&af.TLSKeyFilePass, "tls-keyfile-password", fmtUsage("The password used to decrypt the key-file if encrypted."))
	f.Var(&af.TLSProtocols, "tls-protocols", fmtUsage(
		"Set the TLS protocol selection criteria. This format is the same as"+
			" Apache's SSLProtocol documented at https://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl protocol.",
	))
	// cmd.PersistentFlags().Var(&aerospikeFlags.tlsCipherSuites, "tls-cipher-suites", fmtUsage("Set the TLS protocol selection criteria. This format is the same as Apache's SSLProtocol documented at https://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl protocol."))

	return f
}

func WrapString(val string, lineLen int) string {
	tokens := strings.Split(val, " ")
	currentLen := 0

	for i, tok := range tokens {
		if currentLen+len(tok) > lineLen {
			if i != 0 {
				tok = "\n" + tok
			}

			tokens[i] = tok
			currentLen = 0

			continue
		}

		currentLen += len(tok) + 1 // '\n'
	}

	return strings.Join(tokens, " ")
}

func DefaultWrapHelpString(val string) string {
	return WrapString(val, DefaultMaxLineLength)
}
