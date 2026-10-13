package secretagenttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKI holds the PEM files of a throwaway certificate authority, a server
// certificate valid for 127.0.0.1 and localhost, and a client certificate.
type PKI struct {
	CAFile         string
	ServerCertFile string
	ServerKeyFile  string
	ClientCertFile string
	ClientKeyFile  string
}

// GeneratePKI creates a PKI in dir, for example to configure a real agent in
// end-to-end tests.
func GeneratePKI(dir string) (PKI, error) {
	now := time.Now()
	validity := func(serial int64, name string) x509.Certificate {
		return x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
		}
	}

	caTmpl := validity(1, "secretagenttest CA")
	caTmpl.KeyUsage = x509.KeyUsageCertSign
	caTmpl.BasicConstraintsValid = true
	caTmpl.IsCA = true

	serverTmpl := validity(2, "secretagenttest server")
	serverTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	serverTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverTmpl.DNSNames = []string{"localhost"}
	serverTmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}

	clientTmpl := validity(3, "secretagenttest client")
	clientTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	clientTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	ca, caKey, err := newCertificate(&caTmpl, nil, nil)
	if err != nil {
		return PKI{}, err
	}

	pki := PKI{CAFile: filepath.Join(dir, "ca.pem")}
	if writeErr := writePEM(pki.CAFile, "CERTIFICATE", ca.Raw); writeErr != nil {
		return PKI{}, writeErr
	}

	pki.ServerCertFile, pki.ServerKeyFile, err = issue(dir, "server", &serverTmpl, ca, caKey)
	if err != nil {
		return PKI{}, err
	}

	pki.ClientCertFile, pki.ClientKeyFile, err = issue(dir, "client", &clientTmpl, ca, caKey)
	if err != nil {
		return PKI{}, err
	}

	return pki, nil
}

func issue(
	dir, name string, tmpl, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
) (certFile, keyFile string, err error) {
	cert, key, err := newCertificate(tmpl, ca, caKey)
	if err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("secretagenttest: marshal %s key: %w", name, err)
	}

	certFile = filepath.Join(dir, name+".pem")
	keyFile = filepath.Join(dir, name+"-key.pem")

	if writeErr := writePEM(certFile, "CERTIFICATE", cert.Raw); writeErr != nil {
		return "", "", writeErr
	}

	if writeErr := writePEM(keyFile, "PRIVATE KEY", keyDER); writeErr != nil {
		return "", "", writeErr
	}

	return certFile, keyFile, nil
}

// newCertificate creates a certificate from tmpl signed by parent, or a
// self-signed one when parent is nil.
func newCertificate(
	tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("secretagenttest: generate key: %w", err)
	}

	if parent == nil {
		parent, parentKey = tmpl, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("secretagenttest: create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("secretagenttest: parse certificate: %w", err)
	}

	return cert, key, nil
}

func writePEM(path, blockType string, der []byte) error {
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("secretagenttest: write %s: %w", filepath.Base(path), err)
	}

	return nil
}
