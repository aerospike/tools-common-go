package flags

import (
	as "github.com/aerospike/aerospike-client-go/v8"
	"github.com/aerospike/tools-common-go/client"
	"github.com/spf13/pflag"
)

// AerospikeFlags defines the storage backing
// for Aerospike pflags.FlagSet returned from SetAerospikeFlags.
type AerospikeFlags struct {
	secretRefs           secretRefs
	TLSName              string               `mapstructure:"tls-name"`
	User                 string               `mapstructure:"user"`
	TLSCertFile          CertFlag             `mapstructure:"tls-certfile"`
	Password             PasswordFlag         `mapstructure:"password"`
	TLSRootCAFile        CertFlag             `mapstructure:"tls-cafile"`
	TLSRootCAPath        CertPathFlag         `mapstructure:"tls-capath"`
	TLSKeyFile           CertFlag             `mapstructure:"tls-keyfile"`
	TLSKeyFilePass       PasswordFlag         `mapstructure:"tls-keyfile-password"`
	Seeds                HostTLSPortSliceFlag `mapstructure:"host"`
	AuthMode             AuthModeFlag         `mapstructure:"auth"`
	DefaultPort          int                  `mapstructure:"port"`
	TLSProtocols         TLSProtocolsFlag     `mapstructure:"tls-protocols"`
	TLSEnable            bool                 `mapstructure:"tls-enable"`
	UseServicesAlternate bool                 `mapstructure:"use-services-alternate"`
}

func NewDefaultAerospikeFlags() *AerospikeFlags {
	return &AerospikeFlags{
		Seeds:        NewHostTLSPortSliceFlag(),
		DefaultPort:  DefaultPort,
		TLSProtocols: NewDefaultTLSProtocolsFlag(),
	}
}

// NewFlagSet returns a new pflag.FlagSet with Aerospike flags defined.
// Values set in the returned FlagSet will be stored in the AerospikeFlags argument.
func (af *AerospikeFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}
	f.VarP(&af.Seeds, "host", "h", fmtUsage("The Aerospike host."))
	f.IntVarP(&af.DefaultPort, "port", "p", DefaultPort, fmtUsage("The default Aerospike port."))
	f.StringVarP(&af.User, "user", "U", "", fmtUsage(userUsage))
	f.VarP(&af.Password, "password", "P", fmtUsage("The Aerospike password for the connection to the Aerospike cluster."))
	f.Var(&af.AuthMode, "auth", fmtUsage("The authentication mode used by the Aerospike server."+
		" INTERNAL uses standard user/pass. EXTERNAL uses external methods (like LDAP)"+
		" which are configured on the server. EXTERNAL requires TLS. PKI allows TLS"+
		" authentication and authorization based on a certificate. No username needs to be configured."))
	f.BoolVar(&af.TLSEnable, "tls-enable", false, fmtUsage("Enable TLS authentication with Aerospike."+
		" If false, other TLS options are ignored.",
	))
	f.StringVar(&af.TLSName, "tls-name", "", fmtUsage("The server TLS context to use to"+
		" authenticate the connection to Aerospike.",
	))
	f.Var(&af.TLSRootCAFile, "tls-cafile", fmtUsage("The CA used when connecting to Aerospike."))
	f.Var(&af.TLSRootCAPath, "tls-capath", fmtUsage("A path containing CAs for connecting to Aerospike."))
	f.Var(&af.TLSCertFile, "tls-certfile", fmtUsage("The certificate file for mutual TLS authentication with Aerospike."))
	f.Var(&af.TLSKeyFile, "tls-keyfile", fmtUsage("The key file used for mutual TLS authentication with Aerospike."))
	f.Var(&af.TLSKeyFilePass, "tls-keyfile-password", fmtUsage("The password used to decrypt the key file if encrypted."))
	f.Var(&af.TLSProtocols, "tls-protocols", fmtUsage(
		"Set the TLS protocol selection criteria. This format is the same as"+
			" Apache's SSLProtocol documented at https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslprotocol",
	))
	f.BoolVar(&af.UseServicesAlternate, "services-alternate", false,
		fmtUsage("Determines if the client should use \"services-alternate\" instead of \"services\""+
			" in info request during cluster tending."),
	)

	return f
}

// NewFlagSetWithSecrets is like NewFlagSet, but secrets:[<resource>:]<key>
// values of --user, --password and the TLS file and password options are kept
// as references for ResolveSecrets, which also reads the --password and
// --tls-keyfile-password sources. The usage text of those two flags is already
// wrapped, so fmtUsage is not applied to it.
//
// Call it once per AerospikeFlags, and call ResolveSecrets after parsing:
// until then --password and --tls-keyfile-password hold the text as given.
func (af *AerospikeFlags) NewFlagSetWithSecrets(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := af.NewFlagSet(fmtUsage)
	f.Lookup("user").Usage = fmtUsage(userUsage + " A secrets:<resource>:<key> value is fetched from the Secret Agent.")
	f.Lookup("password").Usage = passwordUsage
	f.Lookup("tls-keyfile-password").Usage = tlsKeyFilePasswordUsage
	af.trackSecretRefs(f)

	return f
}

const userUsage = "The Aerospike user for the connection to the Aerospike cluster."

const passwordUsage = `Password used to authenticate with cluster. Default: none
It can be one of the following:
1) Environment variable: 'env:<VAR>', used exactly as set
2) Base64 encoded environment variable: 'env-b64:<VAR>'
3) Base64 encoded string: 'b64:<BASE64>'
4) File: 'file:<PATH>', the whole file less one trailing '\n' or
   '\r\n'. PATH should name a regular file.
5) Aerospike Secret Agent: 'secrets:<resource>:<key>'
6) String: 'PASSWORD'
Prefixes are case-sensitive. A base64 value may be line wrapped,
and one trailing newline is dropped after decoding. A 'b64:' value
on the command line is as visible as a literal password.
A password that itself begins with 'env:', 'env-b64:', 'b64:',
'file:' or 'secrets:' must be given as 'b64:'.
The password is read only when a user is set and the auth mode is
not PKI. It must be at most 63 bytes.
A value fetched with 'secrets:' is used as-is.`

const tlsKeyFilePasswordUsage = `Password to load protected tls-keyfile.
It can be one of the following:
1) Environment variable: 'env:<VAR>', used exactly as set
2) Base64 encoded environment variable: 'env-b64:<VAR>'
3) Base64 encoded string: 'b64:<BASE64>'
4) File: 'file:<PATH>', the first line of the file
5) Aerospike Secret Agent: 'secrets:<resource>:<key>'
6) String: 'PASSWORD'
Prefixes are case-sensitive. A base64 value may be line wrapped,
and one trailing newline is dropped after decoding.
A password that itself begins with 'env:', 'env-b64:', 'b64:',
'file:' or 'secrets:' must be given as 'b64:'.
Surrounding whitespace is trimmed before the form is read. A
password with surrounding whitespace must be given as 'b64:'.
The password is read only when a key file is set. It must be at
most 1024 bytes.
A value fetched with 'secrets:' is used as-is.
Default: none`

func (af *AerospikeFlags) NewAerospikeConfig() *client.AerospikeConfig {
	aerospikeConf := client.NewDefaultAerospikeConfig()
	aerospikeConf.Seeds = af.Seeds.Seeds
	aerospikeConf.User = af.User
	aerospikeConf.Password = string(af.Password)
	aerospikeConf.AuthMode = as.AuthMode(af.AuthMode)
	aerospikeConf.UseServicesAlternate = af.UseServicesAlternate

	if af.TLSEnable {
		rootCA := [][]byte{}

		if len(af.TLSRootCAFile) != 0 {
			rootCA = append(rootCA, af.TLSRootCAFile)
		}

		rootCA = append(rootCA, af.TLSRootCAPath...)

		aerospikeConf.TLS = client.NewTLSConfig(
			rootCA,
			af.TLSCertFile,
			af.TLSKeyFile,
			af.TLSKeyFilePass,
			af.TLSProtocols.Min,
			af.TLSProtocols.Max,
		)
	}

	for _, elem := range aerospikeConf.Seeds {
		if elem.Port == 0 {
			elem.Port = af.DefaultPort
		}

		if elem.TLSName == "" && af.TLSName != "" {
			elem.TLSName = af.TLSName
		}
	}

	return aerospikeConf
}
