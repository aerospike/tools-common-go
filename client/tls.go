package client

import "crypto/tls"

type TLSProtocol uint16

const (
	VersionTLSDefaultMin = tls.VersionTLS12
	VersionTLSDefaultMax = tls.VersionTLS12
)

func (p TLSProtocol) String() string {
	switch p {
	case tls.VersionTLS10:
		return "TLSV1"
	case tls.VersionTLS11:
		return "TLSV1.1"
	case tls.VersionTLS12:
		return "TLSV1.2"
	}

	return ""
}