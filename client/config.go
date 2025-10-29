package client

import (
	as "github.com/aerospike/aerospike-client-go/v8"
)

// AerospikeConfig represents the intermediate configuration for an Aerospike
// client. This can be constructed directly using flags.AerospikeFlags or
type AerospikeConfig struct {
	Seeds                HostTLSPortSlice
	User                 string
	Password             string
	AuthMode             as.AuthMode
	TLS                  *TLSConfig
	UseServicesAlternate bool
}

// NewDefaultAerospikeConfig creates a new default AerospikeConfig instance.
func NewDefaultAerospikeConfig() *AerospikeConfig {
	return &AerospikeConfig{
		Seeds: HostTLSPortSlice{NewDefaultHostTLSPort()},
	}
}

// NewClientPolicy creates a new Aerospike client policy based on the
// AerospikeConfig.
func (ac *AerospikeConfig) NewClientPolicy() (*as.ClientPolicy, error) {
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
