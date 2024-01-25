package flags

import (
	as "github.com/aerospike/aerospike-client-go/v6"
	"github.com/aerospike/tools-common-go/client"
	"github.com/spf13/pflag"
)

// AerospikeFlags defines the storage backing
// for Aerospike pflags.FlagSet returned from SetAerospikeFlags.
type AerospikeFlags struct {
	Seeds          HostTLSPortSliceFlag `mapstructure:"host"`
	DefaultPort    int                  `mapstructure:"port"`
	User           string               `mapstructure:"user"`
	Password       PasswordFlag         `mapstructure:"password"`
	AuthMode       AuthModeFlag         `mapstructure:"auth"`
	TLSEnable      bool                 `mapstructure:"tls-enable"`
	TLSName        string               `mapstructure:"tls-name"`
	TLSProtocols   TLSProtocolsFlag     `mapstructure:"tls-protocols"`
	TLSRootCAFile  CertFlag             `mapstructure:"tls-cafile"`
	TLSRootCAPath  CertPathFlag         `mapstructure:"tls-capath"`
	TLSCertFile    CertFlag             `mapstructure:"tls-certfile"`
	TLSKeyFile     CertFlag             `mapstructure:"tls-keyfile"`
	TLSKeyFilePass PasswordFlag         `mapstructure:"tls-keyfile-password"`
}

func NewDefaultAerospikeFlags() *AerospikeFlags {
	return &AerospikeFlags{
		Seeds:        NewHostTLSPortSliceFlag(),
		DefaultPort:  DefaultPort,
		TLSProtocols: NewDefaultTLSProtocolsFlag(),
	}
}

// NewAerospikeFlagSet returns a new pflag.FlagSet with Aerospike flags defined.
// Values set in the returned FlagSet will be stored in the AerospikeFlags argument.
func (af *AerospikeFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
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

func (f *AerospikeFlags) NewAerospikeConfig() *client.AerospikeConfig {
	aerospikeConf := client.NewDefaultAerospikeConfig()
	aerospikeConf.Seeds = f.Seeds.Seeds
	aerospikeConf.User = f.User
	aerospikeConf.Password = string(f.Password)
	aerospikeConf.AuthMode = as.AuthMode(f.AuthMode)

	if f.TLSEnable {
		aerospikeConf.Cert = f.TLSCertFile
		aerospikeConf.Key = f.TLSKeyFile
		aerospikeConf.KeyPass = f.TLSKeyFilePass
		aerospikeConf.TLSProtocolsMinVersion = f.TLSProtocols.min
		aerospikeConf.TLSProtocolsMaxVersion = f.TLSProtocols.max

		aerospikeConf.RootCA = [][]byte{}

		if len(f.TLSRootCAFile) != 0 {
			aerospikeConf.RootCA = append(aerospikeConf.RootCA, f.TLSRootCAFile)
		}

		aerospikeConf.RootCA = append(aerospikeConf.RootCA, f.TLSRootCAPath...)
	}

	for _, elem := range aerospikeConf.Seeds {
		if elem.Port == 0 {
			elem.Port = f.DefaultPort
		}

		if elem.TLSName == "" && f.TLSName != "" {
			elem.TLSName = f.TLSName
		}
	}

	return aerospikeConf
}
