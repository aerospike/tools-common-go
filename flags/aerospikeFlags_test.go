package flags

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"testing"
	"time"

	as "github.com/aerospike/aerospike-client-go/v8"
	"github.com/aerospike/tools-common-go/client"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var testTmp = "test-tmp"

var passFile = testTmp + "/file_test.txt"
var passFileTxt = "password-file\n"

var rootCAPath = testTmp + "/root-ca-path/"
var rootCAFile = testTmp + "/root-ca-path/root-ca.pem"
var rootCATxt = "root-ca-cert"
var rootCAFile2 = testTmp + "/root-ca-path/root-ca2.pem"
var rootCATxt2 = "root-ca-cert2"

var certFile = testTmp + "/cert.pem"
var certTxt = "cert"

var keyFile = testTmp + "/key.pem"
var keyTxt = "key"

type FlagsTestSuite struct {
	suite.Suite
}

func (s *FlagsTestSuite) TestNewDefaultAerospikeFlags() {
	defaultAerospikeFlags := NewDefaultAerospikeFlags()

	s.Equal(
		&AerospikeFlags{
			Seeds:        NewHostTLSPortSliceFlag(),
			DefaultPort:  3000,
			TLSProtocols: NewDefaultTLSProtocolsFlag(),
		},
		defaultAerospikeFlags,
	)
}

func (s *FlagsTestSuite) TestNewAerospikeFlagSet() {
	files := []struct {
		file string
		txt  string
	}{
		{passFile, passFileTxt},
		{rootCAFile, rootCATxt},
		{rootCAFile2, rootCATxt2},
		{certFile, certTxt},
		{keyFile, keyTxt},
	}

	err := os.MkdirAll(rootCAPath, 0o0777)
	if err != nil {
		s.FailNow("Failed to create root CA path", err)
	}

	for _, file := range files {
		err := os.WriteFile(file.file, []byte(file.txt), 0o0600)
		s.NoError(err)
	}

	defer func() {
		os.RemoveAll(testTmp)
	}()

	actualFlags := NewDefaultAerospikeFlags()

	flagSet := actualFlags.NewFlagSet(func(str string) string { return str })

	expectedSeeds := NewHostTLSPortSliceFlag()

	err = expectedSeeds.Set("1.1.1.1:TLS-NAME:3002")
	s.NoError(err)

	expectedAuthMode := AuthModeFlag(0)

	err = expectedAuthMode.Set("EXTERNAL")
	s.NoError(err)

	expectedFlags := &AerospikeFlags{
		Seeds:       expectedSeeds,
		DefaultPort: 3001,
		User:        "admin",
		Password:    []byte("admin"),
		AuthMode:    expectedAuthMode,
		TLSEnable:   true,
		TLSName:     "tls-name",
		TLSProtocols: TLSProtocolsFlag{
			Min: tls.VersionTLS13,
			Max: tls.VersionTLS13,
		},
		TLSRootCAFile:        []byte(rootCATxt),
		TLSRootCAPath:        [][]byte{[]byte(rootCATxt), []byte(rootCATxt2)},
		TLSCertFile:          []byte(certTxt),
		TLSKeyFile:           []byte(keyTxt),
		TLSKeyFilePass:       []byte("key-pass"),
		UseServicesAlternate: true,
	}

	err = flagSet.Parse([]string{
		"--host", "1.1.1.1:TLS-NAME:3002",
		"--port", "3001",
		"--user", "admin",
		"--password", "admin",
		"--auth", "EXTERNAL",
		"--tls-enable",
		"--tls-name", "tls-name",
		"--tls-protocols", "-all +TLSv1.3",
		"--tls-cafile", rootCAFile,
		"--tls-capath", rootCAPath,
		"--tls-certfile", certFile,
		"--tls-keyfile", keyFile,
		"--tls-keyfile-password", "key-pass",
		"--services-alternate", "true",
	},
	)

	s.NoError(err)
	s.Equal(expectedFlags, actualFlags)
}

func (s *FlagsTestSuite) TestNewAerospikeConfig() {
	testCases := []struct {
		input  *AerospikeFlags
		output *client.AerospikeConfig
	}{
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: client.HostTLSPortSlice{
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
					Min: tls.VersionTLS11,
					Max: tls.VersionTLS13,
				},
				UseServicesAlternate: true,
			},
			&client.AerospikeConfig{
				Seeds: client.HostTLSPortSlice{
					{
						Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						TLSName: "tls-name-1",
						Port:    3001,
					},
				},
				User:     "admin",
				Password: "admin",
				AuthMode: as.AuthModeExternal,
				TLS: &client.TLSConfig{
					RootCA:                 [][]byte{[]byte("root-ca"), []byte("root-ca2"), []byte("root-ca3")},
					Cert:                   []byte("cert"),
					Key:                    []byte("key"),
					KeyPass:                []byte("key-pass"),
					TLSProtocolsMinVersion: tls.VersionTLS11,
					TLSProtocolsMaxVersion: tls.VersionTLS13,
				},
				UseServicesAlternate: true,
			},
		},
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: client.HostTLSPortSlice{
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
					Min: tls.VersionTLS11,
					Max: tls.VersionTLS13,
				},
			},
			&client.AerospikeConfig{
				Seeds: client.HostTLSPortSlice{
					{
						Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						TLSName: "tls-name-1",
						Port:    3001,
					},
				},
				User:                 "admin",
				Password:             "admin",
				AuthMode:             as.AuthModeExternal,
				UseServicesAlternate: false,
			},
		},
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: client.HostTLSPortSlice{
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
					Min: tls.VersionTLS11,
					Max: tls.VersionTLS13,
				},
			},
			&client.AerospikeConfig{
				Seeds: client.HostTLSPortSlice{
					{
						Host: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						Port: 3002,
					},
				},
				User:     "admin",
				Password: "admin",
				AuthMode: as.AuthModeExternal,
				TLS: &client.TLSConfig{

					RootCA:                 [][]byte{[]byte("root-ca")},
					Cert:                   []byte("cert"),
					Key:                    []byte("key"),
					KeyPass:                []byte("key-pass"),
					TLSProtocolsMinVersion: tls.VersionTLS11,
					TLSProtocolsMaxVersion: tls.VersionTLS13,
				},
			},
		},
		{
			&AerospikeFlags{
				Seeds: HostTLSPortSliceFlag{
					useDefault: false,
					Seeds: client.HostTLSPortSlice{
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
					Min: tls.VersionTLS11,
					Max: tls.VersionTLS13,
				},
			},
			&client.AerospikeConfig{
				Seeds: client.HostTLSPortSlice{
					{
						Host:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
						TLSName: "tls-name",
						Port:    3000,
					},
				},
				User:     "admin",
				Password: "admin",
				AuthMode: as.AuthModeExternal,
				TLS: &client.TLSConfig{

					RootCA:                 [][]byte{[]byte("root-ca")},
					Cert:                   []byte("cert"),
					Key:                    []byte("key"),
					KeyPass:                []byte("key-pass"),
					TLSProtocolsMinVersion: tls.VersionTLS11,
					TLSProtocolsMaxVersion: tls.VersionTLS13,
				},
			},
		},
	}

	for _, tc := range testCases {
		s.T().Run("", func(_ *testing.T) {
			actual := tc.input.NewAerospikeConfig()
			s.Equal(tc.output, actual)
		})
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunFlagsTestSuite(t *testing.T) {
	suite.Run(t, new(FlagsTestSuite))
}

func TestAuthModeRequiresTLS(t *testing.T) {
	t.Parallel()

	const needsTLS = "TLS is required for external or PKI authentication"

	tests := map[string]struct {
		wantErr string
		args    []string
		mode    as.AuthMode
		tls     bool
	}{
		"EXTERNAL without TLS": {args: []string{"--auth", "EXTERNAL"}, wantErr: needsTLS},
		"PKI without TLS":      {args: []string{"--auth", "PKI"}, wantErr: needsTLS},
		"EXTERNAL with TLS": {
			args: []string{"--auth", "EXTERNAL", "--tls-enable"}, mode: as.AuthModeExternal, tls: true,
		},
		"EXTERNAL_INSECURE without TLS": {args: []string{"--auth", "EXTERNAL_INSECURE"}, mode: as.AuthModeExternal},
		"EXTERNAL_INSECURE with TLS": {
			args: []string{"--auth", "EXTERNAL_INSECURE", "--tls-enable"}, mode: as.AuthModeExternal, tls: true,
		},
		"INTERNAL without TLS": {args: []string{"--auth", "INTERNAL"}, mode: as.AuthModeInternal},
		"INTERNAL with TLS": {
			args: []string{"--auth", "INTERNAL", "--tls-enable"}, mode: as.AuthModeInternal, tls: true,
		},
		"PKI with TLS": {args: []string{"--auth", "PKI", "--tls-enable"}, mode: as.AuthModePKI, tls: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			af := NewDefaultAerospikeFlags()
			require.NoError(t, af.NewFlagSet(DefaultWrapHelpString).Parse(append(tt.args, "-U", "admin", "-P", "admin")))

			policy, err := af.NewAerospikeConfig().NewClientPolicy()
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.mode, policy.AuthMode)

			if tt.tls {
				require.NotNil(t, policy.TlsConfig, "--tls-enable must not dial plain TCP")
			} else {
				require.Nil(t, policy.TlsConfig)
			}
		})
	}
}

func TestTLSEnableAloneSpeaksTLS(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"INTERNAL", "EXTERNAL"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })

			af := NewDefaultAerospikeFlags()
			require.NoError(t, af.NewFlagSet(DefaultWrapHelpString).Parse([]string{
				"--host", listener.Addr().String(), "--auth", mode, "--tls-enable", "-U", "admin", "-P", "admin",
			}))

			conf := af.NewAerospikeConfig()
			policy, err := conf.NewClientPolicy()
			require.NoError(t, err)

			policy.Timeout = time.Second

			done := make(chan struct{})

			go func() {
				defer close(done)

				if c, err := as.NewClientWithPolicyAndHost(policy, conf.NewHosts()...); err == nil {
					c.Close()
				}
			}()

			t.Cleanup(func() { <-done })

			require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(5*time.Second)))

			conn, err := listener.Accept()
			require.NoError(t, err, "the client never connected")

			defer conn.Close()

			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

			first := make([]byte, 1)
			_, err = io.ReadFull(conn, first)
			require.NoError(t, err)
			require.Equal(t, byte(0x16), first[0], "first byte is not a TLS handshake record")
		})
	}
}

func TestAuthModeUsage(t *testing.T) {
	usage := NewDefaultAerospikeFlags().NewFlagSet(func(str string) string { return str }).Lookup("auth").Usage

	require.Equal(t, "The authentication mode used by the Aerospike server."+
		" INTERNAL uses standard user/pass. EXTERNAL uses external methods (like LDAP)"+
		" which are configured on the server. EXTERNAL requires TLS. EXTERNAL_INSECURE is EXTERNAL"+
		" without the TLS requirement: without TLS it sends the password in clear, and some tools"+
		" still refuse it without TLS. PKI requires TLS, and allows TLS authentication and"+
		" authorization based on a certificate. No username needs to be configured.", usage)
}

func TestAuthModeFromConfigFile(t *testing.T) {
	af, _, err := loadToolConfig(t, "[cluster]\nauth = \"EXTERNAL_INSECURE\"\n", "")
	require.NoError(t, err)
	require.Equal(t, "EXTERNAL_INSECURE", af.AuthMode.String())
}
