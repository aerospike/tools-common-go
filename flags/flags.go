package flags

import (
	"strings"

	as "github.com/aerospike/aerospike-client-go/v6"
	"github.com/spf13/pflag"
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
		DefaultPort:  DEFAULT_PORT,
		TLSProtocols: NewDefaultTLSProtocolsFlag(),
	}
}

const HELP_MAX_LINE = 65

func wrapString(val string, lineLen int) string {
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

		currentLen += len(tok) + 1 //'\n'
	}

	return strings.Join(tokens, " ")
}

func wrapHelpString(val string) string {
	return wrapString(val, HELP_MAX_LINE)
}

// SetAerospikeConf sets the values in aerospikeConf based the values set in flags.
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

// SetAerospikeFlags returns a new pflag.FlagSet with Aerospike flags defined.
// Values set in the returned FlagSet will be stored in the AerospikeFlags argument.
func SetAerospikeFlags(af *AerospikeFlags) *pflag.FlagSet {
	f := &pflag.FlagSet{}
	f.VarP(&af.Seeds, "host", "h", wrapHelpString("The aerospike host."))
	f.IntVarP(&af.DefaultPort, "port", "p", 3000, wrapHelpString("The default aerospike port."))
	f.StringVarP(&af.User, "user", "U", "", wrapHelpString("The aerospike user to use to connect to the aerospike cluster."))
	f.VarP(&af.Password, "password", "P", wrapHelpString("The aerospike password to use to connect to the aerospike cluster."))
	f.Var(&af.AuthMode, "auth", wrapHelpString("The authentication mode used by the server. INTERNAL uses standard user/pass. EXTERNAL uses external methods (like LDAP) which are configured on the server. EXTERNAL requires TLS. PKI allows TLS authentication and authorization based on a certificate. No user name needs to be configured."))
	f.BoolVar(&af.TLSEnable, "tls-enable", false, wrapHelpString("Enable TLS authentication. If false, other tls options are ignored."))
	f.StringVar(&af.TLSName, "tls-name", "", wrapHelpString("The server TLS context to use to authenticate the connection."))
	f.Var(&af.TLSRootCAFile, "tls-cafile", wrapHelpString("The CA for the agent."))
	f.Var(&af.TLSRootCAPath, "tls-capath", wrapHelpString("A path containing CAs for the agent."))
	f.Var(&af.TLSCertFile, "tls-certfile", wrapHelpString("The certificate file of the agent for mutual TLS authentication."))
	f.Var(&af.TLSKeyFile, "tls-keyfile", wrapHelpString("The key file of the agent for mutual TLS authentication."))
	f.Var(&af.TLSKeyFilePass, "tls-keyfile-password", wrapHelpString("The password used to decrypt the key-file if encrypted."))
	f.Var(&af.TLSProtocols, "tls-protocols", wrapHelpString("Set the TLS protocol selection criteria. This format is the same as Apache's SSLProtocol documented at https://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl protocol."))
	// cmd.PersistentFlags().Var(&aerospikeFlags.tlsCipherSuites, "tls-cipher-suites", wrapHelpString("Set the TLS protocol selection criteria. This format is the same as Apache's SSLProtocol documented at https://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl protocol."))

	return f
}
