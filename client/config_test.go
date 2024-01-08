package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	as "github.com/aerospike/aerospike-client-go/v6"
)

var key, _ = rsa.GenerateKey(rand.Reader, 512)

// Encode private key to PKCS#1 ASN.1 PEM.
var keyFileBytes = pem.EncodeToMemory(
	&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	},
)

// Generate certificate
var tml = x509.Certificate{
	NotBefore:    time.Now(),
	NotAfter:     time.Now().AddDate(5, 0, 0),
	SerialNumber: big.NewInt(123123),
	Subject: pkix.Name{
		CommonName:   "New Name",
		Organization: []string{"New Org."},
	},
	BasicConstraintsValid: true,
}
var cert, _ = x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
var certFileBytes = pem.EncodeToMemory(&pem.Block{
	Type:  "CERTIFICATE",
	Bytes: cert,
})

func TestAerospikeConfig_NewClientPolicy(t *testing.T) {
	config := &AerospikeConfig{
		User:     "testUser",
		Password: "testPassword",
		AuthMode: as.AuthModeExternal,
	}

	expectedClientPolicy := as.NewClientPolicy()
	expectedClientPolicy.User = config.User
	expectedClientPolicy.Password = config.Password
	expectedClientPolicy.AuthMode = config.AuthMode
	expectedClientPolicy.TlsConfig = nil

	clientPolicy, err := config.NewClientPolicy()
	if err != nil {
		t.Errorf("NewClientPolicy() returned an unexpected error: %v", err)
	}

	if !reflect.DeepEqual(clientPolicy, expectedClientPolicy) {
		t.Errorf("NewClientPolicy() returned incorrect ClientPolicy, got %v, want %v", clientPolicy, expectedClientPolicy)
	}
}

func TestAerospikeConfig_NewHosts(t *testing.T) {
	ac := &AerospikeConfig{
		Seeds: HostTLSPortSlice{
			{
				Host:    "localhost",
				Port:    3000,
				TLSName: "example.com",
			},
			{
				Host: "127.0.0.1",
				Port: 4000,
			},
		},
	}

	expectedHosts := []*as.Host{
		{
			Name:    "localhost",
			Port:    3000,
			TLSName: "example.com",
		},
		{
			Name: "127.0.0.1",
			Port: 4000,
		},
	}

	actualHosts := ac.NewHosts()

	if !reflect.DeepEqual(actualHosts, expectedHosts) {
		t.Errorf("NewHosts() returned incorrect hosts, got %v, want %v", actualHosts, expectedHosts)
	}
}

func TestAerospikeConfig_NewTLSConfig(t *testing.T) {
	emptyConfig := &AerospikeConfig{}
	nilTLSConfig, _ := emptyConfig.newTLSConfig()
	if nilTLSConfig != nil {
		t.Errorf("NewTLSConfig() should return nil when config is empty")
	}

	config := &AerospikeConfig{
		RootCA:                 [][]byte{[]byte("fakecert1")},
		Cert:                   certFileBytes,
		Key:                    keyFileBytes,
		KeyPass:                []byte("fakepassphrase"),
		TLSProtocolsMinVersion: 1,
		TLSProtocolsMaxVersion: 3,
	}
	expectedServerPool, _ := x509.SystemCertPool()
	expectedServerPool.AppendCertsFromPEM(config.RootCA[0])
	expectedClientPool, _ := loadServerCertAndKey(config.Cert, config.Key, config.KeyPass)

	tlsConfig, err := config.newTLSConfig()
	if err != nil {
		t.Errorf("NewTLSConfig() returned an unexpected error: %v", err)
	}

	if !reflect.DeepEqual(tlsConfig.RootCAs, expectedServerPool) {
		t.Errorf("NewTLSConfig() returned incorrect RootCAs, got %v, want %v", tlsConfig.RootCAs, expectedServerPool)
	}

	if !reflect.DeepEqual(tlsConfig.Certificates, expectedClientPool) {
		t.Errorf("NewTLSConfig() returned incorrect Certificates, got %v, want %v", tlsConfig.Certificates, expectedClientPool)
	}

	if tlsConfig.InsecureSkipVerify {
		t.Errorf("NewTLSConfig() should have InsecureSkipVerify set to false")
	}

	if !tlsConfig.PreferServerCipherSuites {
		t.Errorf("NewTLSConfig() should have PreferServerCipherSuites set to true")
	}

	if tlsConfig.MinVersion != uint16(config.TLSProtocolsMinVersion) {
		t.Errorf("NewTLSConfig() returned incorrect MinVersion, got %v, want %v", tlsConfig.MinVersion, config.TLSProtocolsMinVersion)
	}

	if tlsConfig.MaxVersion != uint16(config.TLSProtocolsMaxVersion) {
		t.Errorf("NewTLSConfig() returned incorrect MaxVersion, got %v, want %v", tlsConfig.MaxVersion, config.TLSProtocolsMaxVersion)
	}
}

func TestNewDefaultAerospikeHostConfig(t *testing.T) {
	expectedConfig := &AerospikeConfig{
		Seeds: HostTLSPortSlice{NewDefaultHostTLSPort()},
	}

	actualConfig := NewDefaultAerospikeHostConfig()

	if !reflect.DeepEqual(actualConfig, expectedConfig) {
		t.Errorf("NewDefaultAerospikeHostConfig() = %v, want %v", actualConfig, expectedConfig)
	}
}

func TestLoadServerCertAndKey(t *testing.T) {
	keyPassBytes := []byte("fakepassphrase")
	expectedCert, _ := tls.X509KeyPair(certFileBytes, keyFileBytes)

	testCases := []struct {
		name           string
		certFileBytes  []byte
		keyFileBytes   []byte
		keyPassBytes   []byte
		expectedOutput []tls.Certificate
		expectedError  error
	}{
		{
			name:           "ValidCertAndKey",
			certFileBytes:  certFileBytes,
			keyFileBytes:   keyFileBytes,
			keyPassBytes:   keyPassBytes,
			expectedOutput: []tls.Certificate{expectedCert},
			expectedError:  nil,
		},
		{
			name:           "InvalidKeyBlock",
			certFileBytes:  certFileBytes,
			keyFileBytes:   []byte("invalidkeyblock"),
			keyPassBytes:   keyPassBytes,
			expectedOutput: nil,
			expectedError:  fmt.Errorf("failed to decode PEM data for key or certificate"),
		},
		{
			name:           "EncryptedKeyBlock",
			certFileBytes:  certFileBytes,
			keyFileBytes:   encryptPEMBlock(keyFileBytes, keyPassBytes),
			keyPassBytes:   keyPassBytes,
			expectedOutput: []tls.Certificate{expectedCert},
			expectedError:  nil,
		},
		{
			name:           "InvalidPassphrase",
			certFileBytes:  certFileBytes,
			keyFileBytes:   encryptPEMBlock(keyFileBytes, []byte("wrongpassphrase")),
			keyPassBytes:   keyPassBytes,
			expectedOutput: nil,
			expectedError:  fmt.Errorf("failed to decrypt PEM Block: `x509: decryption password incorrect`"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualOutput, actualError := loadServerCertAndKey(tc.certFileBytes, tc.keyFileBytes, tc.keyPassBytes)

			if !reflect.DeepEqual(actualOutput, tc.expectedOutput) {
				t.Errorf("loadServerCertAndKey() output = %v, want %v", actualOutput, tc.expectedOutput)
			}

			if !errorsEqual(actualError, tc.expectedError) {
				t.Errorf("loadServerCertAndKey() error = %v, want %v", actualError, tc.expectedError)
			}
		})
	}
}

func encryptPEMBlock(keyFileBytes, keyPassBytes []byte) []byte {
	block, _ := pem.Decode(keyFileBytes)

	encryptedBlock, _ := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, keyPassBytes, x509.PEMCipherAES256)

	return pem.EncodeToMemory(encryptedBlock)
}

func errorsEqual(err1, err2 error) bool {
	if err1 == nil && err2 == nil {
		return true
	}
	if err1 == nil || err2 == nil {
		return false
	}
	return err1.Error() == err2.Error()
}

func TestLoadCACerts(t *testing.T) {
	cert1 := []byte("fakecert1")
	cert2 := []byte("fakecert2")
	expectedPool, _ := x509.SystemCertPool()
	expectedPool.AppendCertsFromPEM(cert1)
	expectedPool.AppendCertsFromPEM(cert2)

	testCases := []struct {
		name           string
		certsBytes     [][]byte
		expectedOutput *x509.CertPool
	}{
		{
			name:           "ValidCerts",
			certsBytes:     [][]byte{cert1, cert2},
			expectedOutput: expectedPool,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualOutput := loadCACerts(tc.certsBytes)

			if !reflect.DeepEqual(actualOutput, tc.expectedOutput) {
				t.Errorf("loadCACerts() output = %v, want %v", actualOutput, tc.expectedOutput)
			}

		})
	}
}
