package flags

// Basic imports
import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"strings"
	"testing"
	"text/template"

	as "github.com/aerospike/aerospike-client-go/v8"
	"github.com/aerospike/tools-common-go/config"
	"github.com/aerospike/tools-common-go/flags"
	"github.com/aerospike/tools-common-go/testutils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/suite"
)

/*
This file tests the loading of the configuration file and command line arguments.
It tests the behavior of the viper module, cobra, and our own custom built flags.
**/

const (
	testPassword    = "test-password"
	envUser         = "env-user"
	defaultUser     = "default-user"
	defaultPassword = "default-password"
)

var confTomlFile = "conf_test.conf"
var confTomlTemplate = `
# -----------------------------------
# Aerospike tools configuration file.
# -----------------------------------
[cluster]
host = "1.1.1.1:3001,2.2.2.2:3002,3.3.3.3"
user = "` + defaultUser + `"
password = "` + defaultPassword + `"
auth = "EXTERNAL"

[cluster_tls]
port = 4333
host = "3.3.3.3"
tls-name = "tls-name"
tls-enable = true
tls-capath = "{{.RootCAPath}}"
tls-cafile = "{{.RootCAFile}}"
tls-certfile = "{{.CertFile}}"
tls-keyfile = "{{.KeyFile}}"

[cluster_instance]
host = "3.3.3.3:3003,4.4.4.4:3004"
user = "test-user"
password = "` + testPassword + `"

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
password = "file:{{.PassFile}}"

[uda]
agent-port = 8001
store-file = "default1.store"

[uda_instance]
store-file = "test.store"
`

var confYamlFile = "conf_test.yaml"
var confYamlTemplate = `
# -----------------------------------
# Aerospike tools configuration file.
# -----------------------------------
cluster:
  host: "1.1.1.1:3001,2.2.2.2:3002,3.3.3.3"
  user: "` + defaultUser + `"
  password: "default-password"
  auth: "EXTERNAL"

cluster_tls:
  port: 4333
  host: "3.3.3.3"
  tls-name: "tls-name"
  tls-enable: true
  tls-capath: "{{.RootCAPath}}"
  tls-cafile: "{{.RootCAFile}}"
  tls-certfile: "{{.CertFile}}"
  tls-keyfile: "{{.KeyFile}}"

cluster_instance:
  host: "3.3.3.3:3003,4.4.4.4:3004"
  user: "test-user"
  password: "` + testPassword + `"

cluster_env:
  host: "5.5.5.5:env-tls-name:1000"
  password: "env:AEROSPIKE_TEST"

cluster_envb64:
  host: "6.6.6.6:env-tls-name:1000"
  password: "env-b64:AEROSPIKE_TEST"

cluster_b64:
  host: "7.7.7.7:env-tls-name:1000"
  password: "b64:dGVzdC1wYXNzd29yZAo="

cluster_file:
  host: "1.1.1.1"
  password: "file:{{.PassFile}}"

uda:
  agent-port: 8001
  store-file: "default1.store"

uda_instance:
  store-file: "test.store"

`

type ConfTestSuite struct {
	suite.Suite
	files  []string
	tmpDir string

	passFile    string
	passFileTxt string
	rootCAPath  string
	rootCAFile  string
	rootCATxt   string
	rootCAFile2 string
	rootCATxt2  string
	certFile    string
	certTxt     string
	keyFile     string
	keyTxt      string
	keyPassFile string
	keyPassTxt  string

	configFile         string
	configFileTemplate string
}

func (s *ConfTestSuite) SetupSuite() {
	// Encode private key to PKCS#1 ASN.1 PEM.
	rootCertPEM, err := testutils.GenerateCert()
	if err != nil {
		s.FailNow("Failed to generate cert: %w", err)
	}

	rootCertPEM2, err := testutils.GenerateCert()
	if err != nil {
		s.FailNow("Failed to generate cert: %w", err)
	}

	certFileBytes, err := testutils.GenerateCert()
	if err != nil {
		s.FailNow("Failed to generate cert: %w", err)
	}

	s.passFile = "file_test.txt"
	s.passFileTxt = "password-file\n"
	s.rootCAPath = "root-ca-path/"
	s.rootCAFile = "root-ca-path/root-ca.pem"
	s.rootCATxt = string(rootCertPEM)
	s.rootCAFile2 = "root-ca-path/root-ca2.pem"
	s.rootCATxt2 = string(rootCertPEM2)
	s.certFile = "cert.pem"
	s.certTxt = string(certFileBytes)
	s.keyFile = "key.pem"
	s.keyTxt = string(testutils.KeyFileBytes)
	s.keyPassFile = "key-pass.txt"
	s.keyPassTxt = "key-pass"

	wd, err := os.Getwd()
	if err != nil {
		s.FailNow("Failed to get working directory: %w", err)
	}

	s.tmpDir = path.Join(wd, "test-tmp")

	err = os.MkdirAll(path.Join(s.tmpDir, s.rootCAPath), os.ModePerm)
	if err != nil {
		s.FailNow("Failed to create directory: %w", err)
	}

	files := []struct {
		file *string
		txt  string
	}{
		{&s.passFile, s.passFileTxt},
		{&s.rootCAFile, s.rootCATxt},
		{&s.rootCAFile2, s.rootCATxt2},
		{&s.certFile, s.certTxt},
		{&s.keyFile, s.keyTxt},
		{&s.keyPassFile, s.keyPassTxt},
	}

	for _, file := range files {
		*file.file = path.Join(s.tmpDir, *file.file)

		err := os.WriteFile(*file.file, []byte(file.txt), 0o0600)
		if err != nil {
			s.FailNow("Failed to write file", err)
		}

		s.files = append(s.files, *file.file)
	}

	s.rootCAPath = path.Join(s.tmpDir, s.rootCAPath)
	configFileTxt := bytes.Buffer{}
	t := template.Must(template.New("conf").Parse(s.configFileTemplate))
	err = t.Execute(
		&configFileTxt,
		struct {
			RootCAPath  string
			RootCAFile  string
			CertFile    string
			KeyFile     string
			KeyPassFile string
			PassFile    string
		}{
			RootCAPath:  s.rootCAPath,
			RootCAFile:  s.rootCAFile,
			CertFile:    s.certFile,
			KeyFile:     s.keyFile,
			KeyPassFile: s.keyPassFile,
			PassFile:    s.passFile,
		},
	)

	s.NoError(err)

	s.configFile = path.Join(s.tmpDir, s.configFile)

	err = os.WriteFile(s.configFile, configFileTxt.Bytes(), 0o0600)
	if err != nil {
		s.FailNow("Failed to write file: %s", err)
	}

	s.files = append(s.files, []string{s.certFile, s.rootCAPath, s.tmpDir}...)
}

func (s *ConfTestSuite) SetupTest() {
	config.Reset()
}

func (s *ConfTestSuite) TearDownSuite() {
	os.RemoveAll(s.tmpDir)
}

func (s *ConfTestSuite) NewTestCmd() (*cobra.Command, *flags.ConfFileFlags, *flags.AerospikeFlags) {
	configFileFlags := flags.NewConfFileFlags()
	aerospikeFlags := flags.NewDefaultAerospikeFlags()

	testCmd := &cobra.Command{
		Use:   "test",
		Short: "test cmd",
		Run: func(cmd *cobra.Command, _ []string) {
			_, err := config.InitConfig(configFileFlags.File, configFileFlags.Instance, cmd.Flags())
			if err != nil {
				s.FailNow("Failed to initialize config", err)
			}
		},
	}

	cfFlagSet := configFileFlags.NewFlagSet(flags.DefaultWrapHelpString)
	asFlagSet := aerospikeFlags.NewFlagSet(flags.DefaultWrapHelpString)

	testCmd.PersistentFlags().AddFlagSet(cfFlagSet)

	// This is what connects the flags to fields of the same name in the config file.
	config.BindPFlags(asFlagSet, "cluster")

	testCmd.PersistentFlags().AddFlagSet(asFlagSet)
	flags.SetupRoot(testCmd, "Test App", "1.1.1-9-g12345")

	return testCmd, configFileFlags, aerospikeFlags
}

func (s *ConfTestSuite) TestSetupRootVersion() {
	testCmd, _, _ := s.NewTestCmd()
	testCmd.Version = "1"
	stdout := &bytes.Buffer{}

	testCmd.SetArgs([]string{"--version"})
	testCmd.SetOut(stdout)

	s.NoError(testCmd.Execute())

	s.Equal("Test App\nVersion 1.1.1\nBuild g12345\n", stdout.String())

	testCmd.SetArgs([]string{"-V"})

	stdout = &bytes.Buffer{}

	testCmd.SetOut(stdout)
	s.NoError(testCmd.Execute())

	s.Equal("Test App\nVersion 1.1.1\nBuild g12345\n", stdout.String())
}

func (s *ConfTestSuite) TestSetupRootHelp() {
	stdout := &bytes.Buffer{}
	testCmd, _, _ := s.NewTestCmd()

	testCmd.SetArgs([]string{"-u"})
	testCmd.SetErr(stdout)
	testCmd.SetOut(stdout)
	s.NoError(testCmd.Execute())

	s.Equal("test cmd", strings.Split(stdout.String(), "\n")[0])

	stdout = &bytes.Buffer{}

	testCmd.SetArgs([]string{"--help"})
	testCmd.SetErr(stdout)
	testCmd.SetOut(stdout)
	s.NoError(testCmd.Execute())

	s.Equal("test cmd", strings.Split(stdout.String(), "\n")[0])
}

func (s *ConfTestSuite) TestConfigFileDefault() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()
	expectedClientConf.User = defaultUser
	expectedClientConf.Password = defaultPassword
	expectedClientConf.AuthMode = as.AuthModeExternal
	expectedClientHosts := []*as.Host{
		{Name: "1.1.1.1", Port: 3001},
		{Name: "2.2.2.2", Port: 3002},
		{Name: "3.3.3.3", Port: 3003},
	}

	output := bytes.Buffer{}
	testCmd.SetErr(&output)
	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "-p", "3003"})
	s.NoError(testCmd.Execute())

	if output.String() != "" {
		s.Fail("Unexpected error: %s", output.String())
	}

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Equal(expectedClientConf, actualClientConf)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

func (s *ConfTestSuite) TestConfigFileTLS() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()

	expectedServerPool, err := x509.SystemCertPool()
	if err != nil {
		s.FailNow("Failed to get system cert pool: %s", err)
	}

	s.True(expectedServerPool.AppendCertsFromPEM([]byte(s.rootCATxt)))
	s.True(expectedServerPool.AppendCertsFromPEM([]byte(s.rootCATxt2)))

	block, _ := pem.Decode([]byte(s.keyTxt))

	keyPem := pem.EncodeToMemory(block)
	cert, _ := tls.X509KeyPair([]byte(s.certTxt), keyPem)
	expectedClientConf.TlsConfig = &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		RootCAs:                  expectedServerPool,
		Certificates:             []tls.Certificate{cert},
	}

	expectedClientHosts := []*as.Host{
		{Name: "3.3.3.3", TLSName: "tls-name", Port: 4333},
	}

	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "--instance", "tls"})
	s.NoError(testCmd.Execute())

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Assert().True(expectedClientConf.TlsConfig.RootCAs.Equal(actualClientConf.TlsConfig.RootCAs))
	s.True(len(expectedClientConf.TlsConfig.Certificates) == len(actualClientConf.TlsConfig.Certificates))
	s.Assert().True(
		expectedClientConf.TlsConfig.Certificates[0].Leaf.Equal(actualClientConf.TlsConfig.Certificates[0].Leaf),
	)
	s.False(expectedClientConf.TlsConfig.InsecureSkipVerify)
	s.Equal(expectedClientConf.TlsConfig.MinVersion, actualClientConf.TlsConfig.MinVersion)
	s.Equal(expectedClientConf.TlsConfig.MaxVersion, actualClientConf.TlsConfig.MaxVersion)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

func (s *ConfTestSuite) TestConfigFileWithInstance() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()
	expectedClientConf.User = "test-user"
	expectedClientConf.Password = testPassword
	expectedClientHosts := []*as.Host{
		{Name: "3.3.3.3", Port: 3003},
		{Name: "4.4.4.4", Port: 3004},
	}

	output := bytes.Buffer{}
	testCmd.SetErr(&output)
	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "--instance", "instance"})
	s.NoError(testCmd.Execute())

	if output.String() != "" {
		s.Fail("Unexpected error: %s", output.String())
	}

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Equal(expectedClientConf, actualClientConf)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

func (s *ConfTestSuite) TestConfigFileWithEnv() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()
	expectedClientConf.User = envUser
	expectedClientConf.Password = testPassword
	expectedClientHosts := []*as.Host{
		{Name: "5.5.5.5", TLSName: "env-tls-name", Port: 1000},
	}

	os.Setenv("AEROSPIKE_TEST", testPassword)

	output := bytes.Buffer{}
	testCmd.SetErr(&output)
	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "--instance", "env", "--user", envUser})
	s.NoError(testCmd.Execute())

	if output.String() != "" {
		s.Fail("Unexpected error: %s", output.String())
	}

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Equal(expectedClientConf, actualClientConf)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

func (s *ConfTestSuite) TestConfigFileWithEnvB64() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()
	expectedClientConf.User = envUser
	expectedClientConf.Password = testPassword
	expectedClientHosts := []*as.Host{
		{Name: "6.6.6.6", TLSName: "env-tls-name", Port: 1000},
	}

	output := bytes.Buffer{}
	testCmd.SetErr(&output)
	os.Setenv("AEROSPIKE_TEST", "dGVzdC1wYXNzd29yZAo=")
	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "--instance", "envb64", "--user", envUser})
	s.NoError(testCmd.Execute())

	if output.String() != "" {
		s.Fail("Unexpected error: %s", output.String())
	}

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Equal(expectedClientConf, actualClientConf)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

func (s *ConfTestSuite) TestConfigFileWithB64() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()
	expectedClientConf.User = envUser
	expectedClientConf.Password = testPassword
	expectedClientHosts := []*as.Host{
		{
			Name:    "7.7.7.7",
			TLSName: "env-tls-name",
			Port:    1000,
		},
	}

	output := bytes.Buffer{}
	testCmd.SetErr(&output)
	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "--instance", "b64", "--user", envUser})
	s.NoError(testCmd.Execute())

	if output.String() != "" {
		s.Fail("Unexpected error: %s", output.String())
	}

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Equal(expectedClientConf, actualClientConf)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

func (s *ConfTestSuite) TestConfigFileWithFile() {
	testCmd, _, asFlags := s.NewTestCmd()
	expectedClientConf := as.NewClientPolicy()
	expectedClientConf.User = "user"
	expectedClientConf.Password = "password-file"
	expectedClientHosts := []*as.Host{
		{
			Name:    "1.1.1.1",
			TLSName: "",
			Port:    0,
		},
	}

	output := bytes.Buffer{}
	testCmd.SetErr(&output)
	testCmd.SetArgs([]string{"test", "--config-file", s.configFile, "--instance", "file", "--user", "user", "-p", "0"})
	s.NoError(testCmd.Execute())

	if output.String() != "" {
		s.Fail("Unexpected error: %s", output.String())
	}

	aerospikeConf := asFlags.NewAerospikeConfig()

	actualClientConf, err := aerospikeConf.NewClientPolicy()

	s.NoError(err)
	s.Equal(expectedClientConf, actualClientConf)

	actualClientHosts := aerospikeConf.NewHosts()
	s.Equal(expectedClientHosts, actualClientHosts)
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestRunConfTestSuite(t *testing.T) {
	configs := []struct {
		file     string
		template string
	}{
		{confTomlFile, confTomlTemplate},
		{confYamlFile, confYamlTemplate},
	}

	for _, config := range configs {
		cts := new(ConfTestSuite)
		cts.configFile = config.file
		cts.configFileTemplate = config.template
		suite.Run(t, cts)
	}
}
