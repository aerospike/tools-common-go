package flags

// Basic imports
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aerospike/tools-common-go/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

/*
This file tests the loading of the configuration file and command line arguments.
It tests the behavior of the viper module, cobra, and our own custom built flags.
**/

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

var confFile = "conf_test.conf"
var confFileTxt = `
# -----------------------------------
# Aerospike tools configuration file.
# -----------------------------------
[cluster]
host = "1.1.1.1:3001,2.2.2.2:3002"
user = "default-user"
password = "default-password"
auth = "EXTERNAL"

[cluster_tls]
port = 4333
host = "3.3.3.3"
tls-name = "tls-name"
tls-enable = true
tls-capath = "root-ca-path/"
tls-cafile = "root-ca-path/root-ca.pem"
tls-certfile = "cert.pem"
tls-keyfile = "key.pem"
tls-keyfile-password = "file:key-pass.txt"

[cluster_instance]
host = "3.3.3.3:3003,4.4.4.4:3004"
user = "test-user"
password = "test-password"

[cluster_env]
host = "5.5.5.5:env-tls-name:1000"
password = "env:AEROSPIKE_TEST"

[cluster_envb64]
host = "6.6.6.6:env-tls-name:1000"
password = "env-b64:AEROSPIKE_TEST"

[cluster_b64]
host = "7.7.7.7:env-tls-name:1000"
password = "b64:dGVzdC1wYXNzd29yZAo="

[cluster_file]
host = "1.1.1.1"
password = "file:file_test.txt"

[uda]
agent-port = 8001
store-file = "default1.store"

[uda_instance]
store-file = "test.store"
`

type ConfTestSuite struct {
	suite.Suite
	testCmd *cobra.Command
	files   []struct {
		file *string
		txt  string
	}
	aerospikeFlags *AerospikeFlags
	passFile       string
	passFileTxt    string
	rootCAPath     string
	rootCAFile     string
	rootCATxt      string
	rootCAFile2    string
	rootCATxt2     string
	certFile       string
	certTxt        string
	keyFile        string
	keyTxt         string
	keyPassFile    string
	keyPassTxt     string
}

func (suite *ConfTestSuite) SetupSuite() {
	suite.passFile = "file_test.txt"
	suite.passFileTxt = "password-file\n"
	suite.rootCAPath = "root-ca-path/"
	suite.rootCAFile = "root-ca-path/root-ca.pem"
	suite.rootCATxt = "root-ca-cert"
	suite.rootCAFile2 = "root-ca-path/root-ca2.pem"
	suite.rootCATxt2 = "root-ca-cert2"
	suite.certFile = "cert.pem"
	suite.certTxt = string(certFileBytes)
	suite.keyFile = "key.pem"
	suite.keyTxt = string(keyFileBytes)
	suite.keyPassFile = "key-pass.txt"
	suite.keyPassTxt = "key-pass"

	wd, err := os.Getwd()
	if err != nil {
		suite.FailNow("Failed to get working directory: %w", err)
	}

	os.Mkdir(suite.rootCAPath, os.ModePerm)
	suite.files = []struct {
		file *string
		txt  string
	}{
		{&confFile, confFileTxt},
		{&suite.passFile, suite.passFileTxt},
		{&suite.rootCAFile, suite.rootCATxt},
		{&suite.rootCAFile2, suite.rootCATxt2},
		{&suite.certFile, suite.certTxt},
		{&suite.keyFile, suite.keyTxt},
		{&suite.keyPassFile, suite.keyPassTxt},
	}

	for _, file := range suite.files {
		*file.file = path.Join(wd, *file.file)
		os.WriteFile(*file.file, []byte(file.txt), 0666)
	}
}

func (suite *ConfTestSuite) TearDownSuite() {
	for _, file := range suite.files {
		os.Remove(*file.file)
	}

	os.Remove(suite.rootCAPath)
}

func (suite *ConfTestSuite) NewTestCmd() *cobra.Command {
	var configFileFlags = NewConfFileFlags()
	var aerospikeFlags = NewDefaultAerospikeFlags()

	testCmd := &cobra.Command{
		Use: "test",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			_, err := config.InitConfig(configFileFlags.File, configFileFlags.Instance, cmd.Flags())
			if err != nil {
				suite.FailNow("Failed to initialize config: %s", err)
			}
		},
	}

	cfFlagSet := configFileFlags.NewFlagSet(DefaultWrapHelpString)
	testCmd.PersistentFlags().AddFlagSet(cfFlagSet)
	asFlagSet := aerospikeFlags.NewFlagSet(DefaultWrapHelpString)
	testCmd.PersistentFlags().AddFlagSet(asFlagSet)

	return testCmd
}

func (suite *ConfTestSuite) SetupTest() {
	config.Reset()
}

func (suite *ConfTestSuite) TestSetupRoot() {
	testCmd := suite.NewTestCmd()
	testCmd.Version = "1.1.1"
	SetupRoot(testCmd, "Test App")

	testCmd.SetArgs([]string{"--version"})
	var stdout bytes.Buffer
	testCmd.SetOut(&stdout)
	testCmd.Execute()

	suite.Equal(stdout.String(), "Test App version\n1.1.1\n")
}

// func (suite *ConfTestSuite) TestConfigFileDefault() {
// 	expectedArgs := flags.NewDefaultAerospikeFlags()
// 	expectedArgs.Seeds = flags.HostTLSPortSliceFlag{
// 		// useDefault: false,
// 		Seeds: commonClientConf.HostTLSPortSlice{
// 			{
// 				Host:    "1.1.1.1",
// 				TLSName: "",
// 				Port:    3001,
// 			},
// 			{
// 				Host:    "2.2.2.2",
// 				TLSName: "",
// 				Port:    3002,
// 			},
// 		},
// 	}
// 	expectedArgs.DefaultPort = 3000
// 	expectedArgs.User = "default-user"
// 	expectedArgs.Password = []byte("default-password")
// 	expectedArgs.AuthMode = flags.AuthModeFlag(as.AuthModeExternal)

// 	expectedAgentPort := 8001
// 	expectedStoreFile := "default1.store"

// 	suite.testCmd.SetArgs([]string{"start", "--config-file", confFile})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, suite.aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// func (suite *ConfTestSuite) TestConfigFileTLS() {
// 	expectedArgs := flags.NewDefaultAerospikeFlags()
// 	expectedArgs.seeds = flags.HostTLSPortSliceFlag{
// 		default_: false,
// 		Seeds: client.HostTLSPortSlice{
// 			{
// 				Host:    "3.3.3.3",
// 				TLSName: "",
// 				Port:    0,
// 			},
// 		},
// 	}
// 	expectedArgs.defaultPort = 4333
// 	expectedArgs.tlsName = "tls-name"
// 	expectedArgs.tlsEnable = true
// 	expectedArgs.tlsRootCAFile = []byte(rootCATxt)
// 	expectedArgs.tlsRootCAPath = [][]byte{[]byte(rootCATxt), []byte(rootCATxt2)}
// 	expectedArgs.tlsCertFile = []byte(certTxt)
// 	expectedArgs.tlsKeyFile = []byte(keyTxt)
// 	expectedArgs.tlsKeyFilePass = []byte(keyPassTxt)

// 	expectedAgentPort := 8080
// 	expectedStoreFile := "/var/log/aerospike/uda.store"

// 	suite.testCmd.SetArgs([]string{"start", "--config-file", "conf_test.conf", "--instance", "tls"})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// func (suite *ConfTestSuite) TestConfigFileWithInstance() {
// 	expectedArgs := newDefaultAerospikeFlags()
// 	expectedArgs.seeds = HostTLSPortSliceFlag{
// 		default_: false,
// 		Seeds: client.HostTLSPortSlice{
// 			{
// 				Host:    "3.3.3.3",
// 				TLSName: "",
// 				Port:    3003,
// 			},
// 			{
// 				Host:    "4.4.4.4",
// 				TLSName: "",
// 				Port:    3004,
// 			},
// 		},
// 	}
// 	expectedArgs.defaultPort = 3000
// 	expectedArgs.user = "test-user"
// 	expectedArgs.password = []byte("test-password")

// 	expectedAgentPort := 8080
// 	expectedStoreFile := "test.store"

// 	suite.testCmd.SetArgs([]string{"start", "--config-file", confFile, "--instance", "instance"})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, aerospikeFlags, "expected %v, got %v", expectedArgs, aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// func (suite *ConfTestSuite) TestConfigFileWithEnv() {
// 	expectedArgs := newDefaultAerospikeFlags()
// 	expectedArgs.seeds = HostTLSPortSliceFlag{
// 		default_: false,
// 		Seeds: client.HostTLSPortSlice{
// 			{
// 				Host:    "5.5.5.5",
// 				TLSName: "env-tls-name",
// 				Port:    1000,
// 			},
// 		},
// 	}
// 	expectedArgs.defaultPort = 3000
// 	expectedArgs.user = "env-user"
// 	expectedArgs.password = []byte("test-password")
// 	expectedAgentPort := 8080
// 	expectedStoreFile := "/var/log/aerospike/uda.store"

// 	os.Setenv("AEROSPIKE_TEST", "test-password")

// 	suite.testCmd.SetArgs([]string{"start", "--config-file", confFile, "--instance", "env", "--user", "env-user"})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, aerospikeFlags, "expected %v, got %v", expectedArgs, aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// func (suite *ConfTestSuite) TestConfigFileWithEnvB64() {
// 	expectedArgs := newDefaultAerospikeFlags()
// 	expectedArgs.seeds = HostTLSPortSliceFlag{
// 		default_: false,
// 		Seeds: client.HostTLSPortSlice{
// 			{
// 				Host:    "6.6.6.6",
// 				TLSName: "env-tls-name",
// 				Port:    1000,
// 			},
// 		},
// 	}
// 	expectedArgs.defaultPort = 3000
// 	expectedArgs.user = "env-user"
// 	expectedArgs.password = []byte("test-password")
// 	expectedAgentPort := 8080
// 	expectedStoreFile := "/var/log/aerospike/uda.store"

// 	os.Setenv("AEROSPIKE_TEST", "dGVzdC1wYXNzd29yZAo=")
// 	suite.testCmd.SetArgs([]string{"start", "--config-file", confFile, "--instance", "envb64", "--user", "env-user"})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, aerospikeFlags, "expected %v, got %v", expectedArgs, aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// func (suite *ConfTestSuite) TestConfigFileWithB64() {
// 	expectedArgs := newDefaultAerospikeFlags()
// 	expectedArgs.seeds = HostTLSPortSliceFlag{
// 		default_: false,
// 		Seeds: client.HostTLSPortSlice{
// 			{
// 				Host:    "7.7.7.7",
// 				TLSName: "env-tls-name",
// 				Port:    1000,
// 			},
// 		},
// 	}
// 	expectedArgs.defaultPort = 3000
// 	expectedArgs.user = "env-user"
// 	expectedArgs.password = []byte("test-password")
// 	expectedAgentPort := 8080
// 	expectedStoreFile := "/var/log/aerospike/uda.store"

// 	suite.testCmd.SetArgs([]string{"start", "--config-file", confFile, "--instance", "b64", "--user", "env-user"})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, aerospikeFlags, "expected %v, got %v", expectedArgs, aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// func (suite *ConfTestSuite) TestConfigFileWithFile() {
// 	expectedArgs := newDefaultAerospikeFlags()
// 	expectedArgs.seeds = HostTLSPortSliceFlag{
// 		default_: false,
// 		Seeds: client.HostTLSPortSlice{
// 			{
// 				Host:    "1.1.1.1",
// 				TLSName: "",
// 				Port:    0,
// 			},
// 		},
// 	}
// 	expectedArgs.defaultPort = 3000
// 	expectedArgs.user = "user"
// 	expectedArgs.password = []byte("password-file")
// 	expectedAgentPort := 8080
// 	expectedStoreFile := "/var/log/aerospike/uda.store"

// 	suite.testCmd.SetArgs([]string{"start", "--config-file", confFile, "--instance", "file", "--user", "user"})
// 	suite.testCmd.Execute()

// 	suite.Equal(expectedArgs, aerospikeFlags, "expected %v, got %v", expectedArgs, aerospikeFlags)
// 	suite.Equal(expectedAgentPort, agentPort)
// 	suite.Equal(expectedStoreFile, dataStorePath)
// }

// // In order for 'go test' to run this suite, we need to create
// // a normal test function and pass our suite to suite.Run
// func TestRunConfTestSuite(t *testing.T) {
// 	suite.Run(t, new(ConfTestSuite))
// }

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunConfTestSuite(t *testing.T) {
	suite.Run(t, new(ConfTestSuite))
}
