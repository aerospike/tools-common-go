package client

import (
	"errors"

	as "github.com/aerospike/aerospike-client-go/v8"
)

var errAuthModeNeedsTLS = errors.New("TLS is required for external or PKI authentication")

// AerospikeConfig represents the intermediate configuration for an Aerospike
// client. This can be constructed directly using flags.AerospikeFlags or
type AerospikeConfig struct {
	TLS      *TLSConfig
	User     string
	Password string
	Seeds    HostTLSPortSlice
	AuthMode as.AuthMode
	// ExternalInsecure allows external authentication without TLS, which sends
	// the password in clear.
	ExternalInsecure     bool
	UseServicesAlternate bool
}

// NewDefaultAerospikeConfig creates a new default AerospikeConfig instance.
func NewDefaultAerospikeConfig() *AerospikeConfig {
	return &AerospikeConfig{
		Seeds: HostTLSPortSlice{NewDefaultHostTLSPort()},
	}
}

// NewClientPolicy creates a new Aerospike client policy based on the
// AerospikeConfig. External and PKI authentication require TLS, as in the C
// client, unless ExternalInsecure allows external authentication without it.
func (ac *AerospikeConfig) NewClientPolicy() (*as.ClientPolicy, error) {
	if ac.TLS == nil &&
		(ac.AuthMode == as.AuthModePKI || (ac.AuthMode == as.AuthModeExternal && !ac.ExternalInsecure)) {
		return nil, errAuthModeNeedsTLS
	}

	clientPolicy := as.NewClientPolicy()
	clientPolicy.User = ac.User
	clientPolicy.Password = ac.Password
	clientPolicy.AuthMode = ac.AuthMode
	clientPolicy.UseServicesAlternate = ac.UseServicesAlternate

	if ac.TLS != nil {
		tlsConfig, err := ac.TLS.NewGoTLSConfig()
		if err != nil {
			return nil, err
		}

		clientPolicy.TlsConfig = tlsConfig
	}

	return clientPolicy, nil
}

func (ac *AerospikeConfig) NewHosts() []*as.Host {
	hosts := []*as.Host{}

	for _, seed := range ac.Seeds {
		host := as.NewHost(seed.Host, seed.Port)

		if seed.TLSName != "" {
			host.TLSName = seed.TLSName
		}

		hosts = append(hosts, host)
	}

	return hosts
}
