package flags

import (
	"crypto/tls"
	"fmt"
	"strings"
)

const (
	VersionTLSDefaultMin = tls.VersionTLS12
	VersionTLSDefaultMax = tls.VersionTLS12
)

type TLSProtocol uint16

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

// TLSProtocolsFlag defines a Cobra compatible flag
// for dealing with tls protocols.
// Example flags include.
// --tls--protocols
type TLSProtocolsFlag struct {
	min TLSProtocol
	max TLSProtocol
}

func NewDefaultTLSProtocolsFlag() TLSProtocolsFlag {
	return TLSProtocolsFlag{
		min: VersionTLSDefaultMin,
		max: VersionTLSDefaultMax,
	}
}

func (flag *TLSProtocolsFlag) Set(val string) error {
	if val == "" {
		*flag = NewDefaultTLSProtocolsFlag()
		return nil
	}

	tlsV1 := uint8(1 << 0)
	tlsV1_1 := uint8(1 << 1)
	tlsV1_2 := uint8(1 << 2)
	tlsAll := tlsV1 | tlsV1_1 | tlsV1_2
	tokens := strings.Fields(val)
	protocols := uint8(0)
	protocolSlice := []TLSProtocol{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
	}

	for _, tok := range tokens {
		var (
			sign    byte
			current uint8
		)

		if tok[0] == '+' || tok[0] == '-' {
			sign = tok[0]
			tok = tok[1:]
		}

		switch tok {
		case "SSLv2":
			return fmt.Errorf("SSLv2 not supported (RFC 6176)")
		case "SSLv3":
			return fmt.Errorf("SSLv3 not supported")
		case "TLSv1":
			current |= tlsV1
		case "TLSv1.1":
			current |= tlsV1_1
		case "TLSv1.2":
			current |= tlsV1_2
		case "all":
			current |= tlsAll
		default:
			return fmt.Errorf("unknown protocol version %s", tok)
		}

		switch sign {
		case '+':
			protocols |= current
		case '-':
			protocols &= ^current
		default:
			if protocols != 0 {
				return fmt.Errorf("TLS protocol %s overrides already set parameters. Check if a +/- prefix is missing", tok)
			}

			protocols = current
		}
	}

	if protocols == tlsAll {
		flag.min = tls.VersionTLS10
		flag.max = tls.VersionTLS12

		return nil
	}

	if (protocols&tlsV1) != 0 && (protocols&tlsV1_2) != 0 {
		// Since golangs tls.Config only support min and max we cannot specify 1 & 1.2 without 1.1
		return fmt.Errorf("you may only specify a range of protocols")
	}

	for i, p := range protocolSlice {
		if protocols&(1<<i) != 0 {
			flag.min = p
			break
		}
	}

	for i := 0; i < len(protocolSlice); i++ {
		p := protocolSlice[len(protocolSlice)-1-i]
		if protocols&((1<<(len(protocolSlice)-1))>>i) != 0 {
			flag.max = p
			break
		}
	}

	return nil
}

func (flag *TLSProtocolsFlag) Type() string {
	return "\"[[+][-]all] [[+][-]TLSv1] [[+][-]TLSv1.1] [[+][-]TLSv1.2]\""
}

func (flag *TLSProtocolsFlag) String() string {
	if flag.min == flag.max {
		return flag.max.String()
	}

	if flag.min == tls.VersionTLS10 && flag.max == tls.VersionTLS12 {
		return "all"
	}

	return flag.min.String() + "," + flag.max.String()
}
