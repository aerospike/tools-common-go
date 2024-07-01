package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type TLSProtocol uint16

const (
	VersionTLSDefaultMin = tls.VersionTLS12
	VersionTLSDefaultMax = tls.VersionTLS13
)

func (p TLSProtocol) String() string {
	switch p {
	case tls.VersionTLS10:
		return "TLSV1"
	case tls.VersionTLS11:
		return "TLSV1.1"
	case tls.VersionTLS12:
		return "TLSV1.2"
	case tls.VersionTLS13:
		return "TLSV1.3"
	}

	return ""
}

// TLSConfig is a struct that holds the TLS configuration for the client. It is
// an intermediate type that integrates nicely with our flags.
type TLSConfig struct {
	RootCA                 [][]byte
	Cert                   []byte
	Key                    []byte
	KeyPass                []byte
	TLSProtocolsMinVersion TLSProtocol
	TLSProtocolsMaxVersion TLSProtocol
	// TLSCipherSuites        []uint16 // TODO
}

// NewTLSConfig returns a new TLSConfig that can later be used to create a
// tls.Config that can be passed to a go client. It is a intermediate type that
// integrates nicely with our flags.
//
//nolint:gocritic // Not sure why this is giving a builtinShadow error with min
func NewTLSConfig(rootCA [][]byte, cert, key, keyPass []byte, min, max TLSProtocol) *TLSConfig {
	return &TLSConfig{
		RootCA:                 rootCA,
		Cert:                   cert,
		Key:                    key,
		KeyPass:                keyPass,
		TLSProtocolsMinVersion: min,
		TLSProtocolsMaxVersion: max,
	}
}

func (tc *TLSConfig) NewGoTLSConfig() (*tls.Config, error) {
	if len(tc.RootCA) == 0 && len(tc.Cert) == 0 && len(tc.Key) == 0 {
		return nil, nil
	}

	var (
		clientPool []tls.Certificate
		serverPool *x509.CertPool
		err        error
	)

	serverPool = LoadCACerts(tc.RootCA)

	if len(tc.Cert) > 0 || len(tc.Key) > 0 {
		clientPool, err = LoadServerCertAndKey(tc.Cert, tc.Key, tc.KeyPass)
		if err != nil {
			return nil, fmt.Errorf("failed to load client authentication certificate and key `%s`", err)
		}
	}

	tlsConfig := &tls.Config{ //nolint:gosec // aerospike default tls version is TLSv1.2
		Certificates:             clientPool,
		RootCAs:                  serverPool,
		InsecureSkipVerify:       false,
		PreferServerCipherSuites: true,
		MinVersion:               uint16(tc.TLSProtocolsMinVersion),
		MaxVersion:               uint16(tc.TLSProtocolsMaxVersion),
	}

	return tlsConfig, nil
}

// LoadCACerts returns CA set of certificates (cert pool)
// reads CA certificate based on the certConfig and adds it to the pool
func LoadCACerts(certsBytes [][]byte) *x509.CertPool {
	certificates, err := x509.SystemCertPool()
	if certificates == nil || err != nil {
		certificates = x509.NewCertPool()
	}

	for _, cert := range certsBytes {
		if len(cert) > 0 {
			certificates.AppendCertsFromPEM(cert)
		}
	}

	return certificates
}

// LoadServerCertAndKey reads server certificate and associated key file based on certConfig and keyConfig
// returns parsed server certificate
// if the private key is encrypted, it will be decrypted using key file passphrase
func LoadServerCertAndKey(certFileBytes, keyFileBytes, keyPassBytes []byte) ([]tls.Certificate, error) {
	var certificates []tls.Certificate

	// Decode PEM data
	keyBlock, _ := pem.Decode(keyFileBytes)

	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM data for key or certificate")
	}

	// Check and Decrypt the Key Block using passphrase
	if x509.IsEncryptedPEMBlock(keyBlock) { //nolint:staticcheck,lll // This needs to be addressed by aerospike as multiple projects require this functionality
		decryptedDERBytes, err := x509.DecryptPEMBlock(keyBlock, keyPassBytes) //nolint:staticcheck,lll // This needs to be addressed by aerospike as multiple projects require this functionality
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
