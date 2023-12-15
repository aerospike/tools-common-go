package flags

import (
	"crypto/tls"
	"testing"

	as "github.com/aerospike/aerospike-client-go/v6"
	"github.com/stretchr/testify/suite"
)

type FlagsTestSuite struct {
	suite.Suite
}

func (suite *FlagsTestSuite) TestSetAerospikeConf() {
	testCases := []struct {
		input  *AerospikeFlags
		output *AerospikeConfig
	}{
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: HostTLSPortSlice{
						{
							Host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						},
					},
				},
				DefaultPort:    3001,
				User:           "admin",
				Password:       []byte("admin"),
				TLSEnable:      true,
				AuthMode:       AuthModeFlag(as.AuthModeExternal),
				TLSRootCAFile:  []byte("root-ca"),
				TLSRootCAPath:  [][]byte{[]byte("root-ca2"), []byte("root-ca3")},
				TLSCertFile:    []byte("cert"),
				TLSKeyFile:     []byte("key"),
				TLSKeyFilePass: []byte("key-pass"),
				TLSName:        "tls-name-1",
				TLSProtocols: TLSProtocolsFlag{
					min: tls.VersionTLS11,
					max: tls.VersionTLS13,
				},
			},
			&AerospikeConfig{
				Seeds: HostTLSPortSlice{
					{
						Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						TLSName: "tls-name-1",
						Port:    3001,
					},
				},
				User:                   "admin",
				Password:               "admin",
				AuthMode:               as.AuthModeExternal,
				RootCA:                 [][]byte{[]byte("root-ca"), []byte("root-ca2"), []byte("root-ca3")},
				Cert:                   []byte("cert"),
				Key:                    []byte("key"),
				KeyPass:                []byte("key-pass"),
				TLSProtocolsMinVersion: tls.VersionTLS11,
				TLSProtocolsMaxVersion: tls.VersionTLS13,
			},
		},
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: HostTLSPortSlice{
						{
							Host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						},
					},
				},
				DefaultPort:    3001,
				User:           "admin",
				Password:       []byte("admin"),
				TLSEnable:      false,
				AuthMode:       AuthModeFlag(as.AuthModeExternal),
				TLSRootCAFile:  []byte("root-ca"),
				TLSCertFile:    []byte("cert"),
				TLSKeyFile:     []byte("key"),
				TLSKeyFilePass: []byte("key-pass"),
				TLSName:        "tls-name-1",
				TLSProtocols: TLSProtocolsFlag{
					min: tls.VersionTLS11,
					max: tls.VersionTLS13,
				},
			},
			&AerospikeConfig{
				Seeds: HostTLSPortSlice{
					{
						Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						TLSName: "tls-name-1",
						Port:    3001,
					},
				},
				User:     "admin",
				Password: "admin",
				AuthMode: as.AuthModeExternal,
			},
		},
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: HostTLSPortSlice{
						{
							Host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
							Port: 3002,
						},
					},
				},
				DefaultPort:    3000,
				User:           "admin",
				Password:       []byte("admin"),
				AuthMode:       AuthModeFlag(as.AuthModeExternal),
				TLSEnable:      true,
				TLSRootCAFile:  []byte("root-ca"),
				TLSCertFile:    []byte("cert"),
				TLSKeyFile:     []byte("key"),
				TLSKeyFilePass: []byte("key-pass"),
				TLSProtocols: TLSProtocolsFlag{
					min: tls.VersionTLS11,
					max: tls.VersionTLS13,
				},
			},
			&AerospikeConfig{
				Seeds: HostTLSPortSlice{
					{
						Host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						Port: 3002,
					},
				},
				User:                   "admin",
				Password:               "admin",
				AuthMode:               as.AuthModeExternal,
				RootCA:                 [][]byte{[]byte("root-ca")},
				Cert:                   []byte("cert"),
				Key:                    []byte("key"),
				KeyPass:                []byte("key-pass"),
				TLSProtocolsMinVersion: tls.VersionTLS11,
				TLSProtocolsMaxVersion: tls.VersionTLS13,
			},
		},
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: HostTLSPortSlice{
						{
							Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
							TLSName: "tls-name",
						},
					},
				},
				DefaultPort:    3000,
				User:           "admin",
				Password:       []byte("admin"),
				AuthMode:       AuthModeFlag(as.AuthModeExternal),
				TLSEnable:      true,
				TLSRootCAFile:  []byte("root-ca"),
				TLSCertFile:    []byte("cert"),
				TLSKeyFile:     []byte("key"),
				TLSKeyFilePass: []byte("key-pass"),
				TLSName:        "not-tls-name",
				TLSProtocols: TLSProtocolsFlag{
					min: tls.VersionTLS11,
					max: tls.VersionTLS13,
				},
			},
			&AerospikeConfig{
				Seeds: HostTLSPortSlice{
					{
						Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						TLSName: "tls-name",
						Port:    3000,
					},
				},
				User:                   "admin",
				Password:               "admin",
				AuthMode:               as.AuthModeExternal,
				RootCA:                 [][]byte{[]byte("root-ca")},
				Cert:                   []byte("cert"),
				Key:                    []byte("key"),
				KeyPass:                []byte("key-pass"),
				TLSProtocolsMinVersion: tls.VersionTLS11,
				TLSProtocolsMaxVersion: tls.VersionTLS13,
			},
		},
	}

	for _, tc := range testCases {
		suite.T().Run("", func(t *testing.T) {
			actual := &AerospikeConfig{}
			SetAerospikeConf(actual, tc.input)
			suite.Equal(tc.output, actual)
		})

	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunFlagsTestSuite(t *testing.T) {
	suite.Run(t, new(FlagsTestSuite))
}
