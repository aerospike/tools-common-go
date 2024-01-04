package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	as "github.com/aerospike/aerospike-client-go/v6"
)

const (
	defaultTimeout      = 5 * time.Second
	defaultTendInterval = 5 * time.Second
)

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

func NewDefaultAerospikeHostConfig() *AerospikeConfig {
	return &AerospikeConfig{
		Seeds: HostTLSPortSlice{NewDefaultHostTLSPort()},
	}
}

func (config *AerospikeConfig) NewClientPolicy() (*as.ClientPolicy, error) {
	clientPolicy := as.NewClientPolicy()
	clientPolicy.User = config.User
	clientPolicy.Password = config.Password
	clientPolicy.Timeout = defaultTimeout
	clientPolicy.AuthMode = config.AuthMode
	clientPolicy.TendInterval = defaultTendInterval

	tlsConfig, err := config.newTLSConfig()

	if err != nil {
		return nil, err
	}

	clientPolicy.TlsConfig = tlsConfig

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

func (config *AerospikeConfig) newTLSConfig() (*tls.Config, error) {
	if len(config.RootCA) == 0 && len(config.Cert) == 0 && len(config.Key) == 0 {
		return nil, nil
	}

	var clientPool []tls.Certificate
	var serverPool *x509.CertPool
	var err error

	serverPool, err = loadCACerts(config.RootCA)

	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificates: `%s`", err)
	}

	if len(config.Cert) > 0 || len(config.Key) > 0 {
		clientPool, err = loadServerCertAndKey(config.Cert, config.Key, config.KeyPass)
		if err != nil {
			return nil, fmt.Errorf("failed to load server certificate and key: `%s`", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates:             clientPool,
		RootCAs:                  serverPool,
		InsecureSkipVerify:       false,
		PreferServerCipherSuites: true,
		MinVersion:               uint16(config.TLSProtocolsMinVersion),
		MaxVersion:               uint16(config.TLSProtocolsMaxVersion),
	}

	return tlsConfig, nil
}

// loadCACerts returns CA set of certificates (cert pool)
// reads CA certificate based on the certConfig and adds it to the pool
func loadCACerts(certsBytes [][]byte) (*x509.CertPool, error) {
	certificates, err := x509.SystemCertPool()
	if certificates == nil || err != nil {
		certificates = x509.NewCertPool()
	}

	for _, cert := range certsBytes {
		if len(cert) > 0 {
			certificates.AppendCertsFromPEM(cert)
		}
	}

	return certificates, nil
}

// loadServerCertAndKey reads server certificate and associated key file based on certConfig and keyConfig
// returns parsed server certificate
// if the private key is encrypted, it will be decrypted using key file passphrase
func loadServerCertAndKey(certFileBytes, keyFileBytes, keyPassBytes []byte) ([]tls.Certificate, error) {
	var certificates []tls.Certificate

	// Decode PEM data
	keyBlock, _ := pem.Decode(keyFileBytes)

	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM data for key or certificate")
	}

	// Check and Decrypt the Key Block using passphrase
	if x509.IsEncryptedPEMBlock(keyBlock) {

		decryptedDERBytes, err := x509.DecryptPEMBlock(keyBlock, keyPassBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PEM Block: `%s`", err)
		}

		keyBlock.Bytes = decryptedDERBytes
		keyBlock.Headers = nil
	}

	// Encode PEM data
	keyPEM := pem.EncodeToMemory(keyBlock)

	if keyPEM == nil {
		return nil, fmt.Errorf("failed to encode PEM data for key or certificate")
	}

	cert, err := tls.X509KeyPair(certFileBytes, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to add certificate and key to the pool: `%s`", err)
	}

	certificates = append(certificates, cert)

	return certificates, nil
}
