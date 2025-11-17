package flags

import (
	"crypto/tls"
	"testing"

	"github.com/aerospike/tools-common-go/client"
	"github.com/stretchr/testify/suite"
)

type TLSModeTestSuite struct {
	suite.Suite
}

func (s *FlagsTestSuite) TestTLSProtocolsFlag() {
	testCases := []struct {
		input  string
		output TLSProtocolsFlag
		err    bool
	}{
		{
			"",
			TLSProtocolsFlag{
				Min: client.VersionTLSDefaultMin,
				Max: client.VersionTLSDefaultMax,
			},
			false,
		},
		{
			"all",
			TLSProtocolsFlag{
				Min: tls.VersionTLS10,
				Max: tls.VersionTLS13,
			},
			false,
		},
		{
			"all -TLSv1",
			TLSProtocolsFlag{
				Min: tls.VersionTLS11,
				Max: tls.VersionTLS13,
			},
			false,
		},
		{
			"all -TLSv1.2",
			TLSProtocolsFlag{
				Min: tls.VersionTLS10,
				Max: tls.VersionTLS13,
			},
			false,
		},
		{
			"+TLSv1",
			TLSProtocolsFlag{
				Min: tls.VersionTLS10,
				Max: tls.VersionTLS10,
			},
			false,
		},
		{
			"+TLSv1.1",
			TLSProtocolsFlag{
				Min: tls.VersionTLS11,
				Max: tls.VersionTLS11,
			},
			false,
		},
		{
			"+TLSv1.2",
			TLSProtocolsFlag{
				Min: tls.VersionTLS12,
				Max: tls.VersionTLS12,
			},
			false,
		},
		{
			"+TLSv1.3",
			TLSProtocolsFlag{
				Min: tls.VersionTLS13,
				Max: tls.VersionTLS13,
			},
			false,
		},
		{
			"all -TLSv1.1",
			TLSProtocolsFlag{
				Min: tls.VersionTLS12,
				Max: tls.VersionTLS13,
			},
			true,
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.input, func(_ *testing.T) {
			var actual TLSProtocolsFlag

			err := actual.Set(tc.input)

			if tc.err {
				s.Error(err)
			} else {
				s.NoError(err)
				s.Equal(tc.output, actual)
			}
		})
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunTLSModeTestSuite(t *testing.T) {
	suite.Run(t, new(AuthModeTestSuite))
}
