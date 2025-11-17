package flags

import (
	"strings"
	"testing"

	as "github.com/aerospike/aerospike-client-go/v8"
	"github.com/stretchr/testify/suite"
)

type AuthModeTestSuite struct {
	suite.Suite
}

func (s *AuthModeTestSuite) TestAuthModeFlag() {
	testCases := []struct {
		input  string
		output AuthModeFlag
	}{
		{
			"INTERNAL",
			AuthModeFlag(as.AuthModeInternal),
		},
		{
			"EXTERNAL",
			AuthModeFlag(as.AuthModeExternal),
		},
		{
			"PKI",
			AuthModeFlag(as.AuthModePKI),
		},
		{
			"internal",
			AuthModeFlag(as.AuthModeInternal),
		},
		{
			"external",
			AuthModeFlag(as.AuthModeExternal),
		},
		{
			"pki",
			AuthModeFlag(as.AuthModePKI),
		},
	}

	for _, tc := range testCases {
		s.T().Run(tc.input, func(_ *testing.T) {
			var actual AuthModeFlag

			s.NoError(actual.Set(tc.input))
			s.Equal(actual, tc.output)
			s.Equal(actual.String(), strings.ToUpper(tc.input))
			s.Equal(actual.Type(), "INTERNAL,EXTERNAL,PKI")
		})
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunAuthModeTestSuite(t *testing.T) {
	suite.Run(t, new(AuthModeTestSuite))
}
