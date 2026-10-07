package secretagent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSOptions describes a TLS connection to the agent using PEM files.
type TLSOptions struct {
	// CAFile verifies the agent certificate. TLS is off when it is empty.
	CAFile string
	// CertFile and KeyFile enable mutual TLS. Set both or neither.
	CertFile string
	KeyFile  string
	// ServerName overrides the name checked against the agent certificate.
	ServerName string
	// MinVersion is a crypto/tls version constant. Zero means TLS 1.2.
	MinVersion uint16
}

// NewTLSConfig builds a TLS configuration from opts. It returns nil, meaning
// plaintext, when opts.CAFile is empty and no client certificate is set.
func NewTLSConfig(opts TLSOptions) (*tls.Config, error) {
	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return nil, fmt.Errorf("%w: TLS cert file and key file must be set together", ErrInvalidConfig)
	}

	if opts.CAFile == "" {
		if opts.CertFile != "" {
			return nil, fmt.Errorf("%w: TLS client certificate requires a CA file", ErrInvalidConfig)
		}

		return nil, nil
	}

	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read TLS CA file: %w", ErrInvalidConfig, err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: no certificates found in TLS CA file %s", ErrInvalidConfig, opts.CAFile)
	}

	cfg := &tls.Config{
		RootCAs:    roots,
		ServerName: opts.ServerName,
		MinVersion: tls.VersionTLS12,
	}

	if opts.MinVersion != 0 {
		cfg.MinVersion = opts.MinVersion
	}

	if opts.CertFile != "" {
		cert, loadErr := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if loadErr != nil {
			return nil, fmt.Errorf("%w: load TLS client certificate: %w", ErrInvalidConfig, loadErr)
		}

		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}
