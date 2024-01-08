package flags

import (
	"testing"

	"github.com/aerospike/tools-common-go/client"
	"github.com/stretchr/testify/suite"
)

type HostTestSuite struct {
	suite.Suite
}

func (suite *HostTestSuite) TestHostTLSPort() {
	testCases := []struct {
		input  string
		output HostTLSPortSliceFlag
	}{
		{
			"127.0.0.1",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "127.0.0.1",
					},
				},
			},
		},
		{
			"127.0.0.1,127.0.0.2",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "127.0.0.1",
					},
					{
						Host: "127.0.0.2",
					},
				},
			},
		},
		{
			"127.0.0.2:3002",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "127.0.0.2",
						Port: 3002,
					},
				},
			},
		},
		{
			"127.0.0.2:3002,127.0.0.3:3003",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "127.0.0.2",
						Port: 3002,
					},
					{
						Host: "127.0.0.3",
						Port: 3003,
					},
				},
			},
		},
		{
			"127.0.0.3:tls-name:3003",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host:    "127.0.0.3",
						TLSName: "tls-name",
						Port:    3003,
					},
				},
			},
		},
		{
			"127.0.0.3:tls-name:3003,127.0.0.4:tls-name4:3004",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host:    "127.0.0.3",
						TLSName: "tls-name",
						Port:    3003,
					},
					{
						Host:    "127.0.0.4",
						TLSName: "tls-name4",
						Port:    3004,
					},
				},
			},
		},
		{
			"127.0.0.3:3003,127.0.0.4:tls-name4:3004",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "127.0.0.3",
						Port: 3003,
					},
					{
						Host:    "127.0.0.4",
						TLSName: "tls-name4",
						Port:    3004,
					},
				},
			},
		},
		{
			"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
					},
				},
			},
		},
		{
			"[fe80::1ff:fe23:4567:890a]:3002",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host: "fe80::1ff:fe23:4567:890a",
						Port: 3002,
					},
				},
			},
		},
		{
			"[100::]:tls-name:3003",
			HostTLSPortSliceFlag{
				useDefault: false,
				Seeds: client.HostTLSPortSlice{
					{
						Host:    "100::",
						TLSName: "tls-name",
						Port:    3003,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.input, func(t *testing.T) {
			actual := NewHostTLSPortSliceFlag()
			actual.Set(tc.input)
			suite.Equal(actual, tc.output)
		})

	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunHostTestSuite(t *testing.T) {
	suite.Run(t, new(HostTestSuite))
}
