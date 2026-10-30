package config

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const tomlConfigTxt = `
[group1]
str="localhost:3000"
int=3000
bool=true

[group2]
str2="localhost:4000"
int2=4000
bool2=false

[group1_instance]
str="localhost:3000 instance"
int=5000
bool=true
`

const yamlConfigTxt = `
group1:
  str: "localhost:3000"
  int:  3000
  bool:  true

group2:
  str2: "localhost:4000"
  int2: 4000
  bool2: false

group1_instance:
  str: "localhost:3000 instance"
  int: 5000
  bool: true
  `

type ConfigTestSuite struct {
	suite.Suite
	tmpDir        string
	file          string
	fileTxt       string
	actualCfgFile string
}

func (s *ConfigTestSuite) SetupSuite() {
	wd, _ := os.Getwd()
	s.tmpDir = path.Join(wd, "test-tmp")
	s.file = path.Join(wd, "test-tmp", s.file)

	err := os.MkdirAll(s.tmpDir, 0o0777)
	if err != nil {
		s.FailNow("Failed to create tmp dir", err)
	}

	err = os.WriteFile(s.file, []byte(s.fileTxt), 0o0600)
	if err != nil {
		s.FailNow("Failed to write config file", err)
	}
}

func (s *ConfigTestSuite) TearDownSuite() {
	os.RemoveAll(s.tmpDir)
}

func (s *ConfigTestSuite) SetupTest() {
	Reset()
}

func (s *ConfigTestSuite) NewCmds(file, instance string) (rootCmd, cmd1, cmd2 *cobra.Command) {
	rootCmd = &cobra.Command{
		Use: "test",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			cfgFileTmp, err := InitConfig(file, instance, cmd.Flags())
			if err != nil {
				return fmt.Errorf("Failed to initialize config: %s", err)
			}

			s.actualCfgFile = cfgFileTmp

			return nil
		},
	}

	cmd1 = &cobra.Command{
		Use: "test1",
		Run: func(_ *cobra.Command, _ []string) {
		},
	}

	cmd2 = &cobra.Command{
		Use: "test2",
		Run: func(_ *cobra.Command, _ []string) {
		},
	}

	rootCmd.AddCommand(cmd1)
	rootCmd.AddCommand(cmd2)

	return rootCmd, cmd1, cmd2
}

// Helper method to assert flag values and reduce code duplication
func (s *ConfigTestSuite) assertFlagValues(cmd *cobra.Command, expectedStr string, expectedInt int, expectedBool bool) {
	str, err := cmd.Flags().GetString("str")
	s.NoError(err)
	s.Equal(expectedStr, str)

	intVal, err := cmd.Flags().GetInt("int")
	s.NoError(err)
	s.Equal(expectedInt, intVal)

	boolVal, err := cmd.Flags().GetBool("bool")
	s.NoError(err)
	s.Equal(expectedBool, boolVal)
}

// Tests the whether different flags on different cmcan read the same values
// from the config file.
func (s *ConfigTestSuite) TestInitConfigWithDuplicateFlags() {
	rootCmd, cmd1, cmd2 := s.NewCmds(s.file, "")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")
	BindPFlags(flagSet, "group1")

	flagSet2 := &pflag.FlagSet{}
	flagSet2.String("str", "", "string flag")
	flagSet2.Int("int", 0, "int flag")
	flagSet2.Bool("bool", false, "bool flag")
	BindPFlags(flagSet2, "group1")

	cmd1.Flags().AddFlagSet(flagSet)
	cmd2.Flags().AddFlagSet(flagSet2)

	// Cmd1
	rootCmd.SetArgs([]string{"test1"})
	err := rootCmd.Execute()

	s.NoError(err)

	str, err := cmd1.Flags().GetString("str")
	s.NoError(err)
	s.Equal("localhost:3000", str)

	intVal, err := cmd1.Flags().GetInt("int")
	s.NoError(err)
	s.Equal(3000, intVal)

	boolVal, err := cmd1.Flags().GetBool("bool")
	s.NoError(err)
	s.Equal(true, boolVal)

	// Cmd2
	rootCmd.SetArgs([]string{"test2"})
	err = rootCmd.Execute()

	s.NoError(err)

	str, err = cmd2.Flags().GetString("str")
	s.NoError(err)
	s.Equal("localhost:3000", str)

	intVal, err = cmd2.Flags().GetInt("int")
	s.NoError(err)
	s.Equal(3000, intVal)

	boolVal, err = cmd2.Flags().GetBool("bool")
	s.NoError(err)
	s.Equal(true, boolVal)

	s.Equal(s.actualCfgFile, s.file)
}

func (s *ConfigTestSuite) TestInitConfigWithMultiSections() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")
	BindPFlags(flagSet, "group1")

	flagSet2 := &pflag.FlagSet{}
	flagSet2.String("str2", "", "string flag")
	flagSet2.Int("int2", 0, "int flag")
	flagSet2.Bool("bool2", false, "bool flag")
	BindPFlags(flagSet2, "group2")

	cmd1.Flags().AddFlagSet(flagSet2)
	cmd1.Flags().AddFlagSet(flagSet)

	// Cmd1
	rootCmd.SetArgs([]string{"test1"})
	err := rootCmd.Execute()

	s.NoError(err)

	str, err := cmd1.Flags().GetString("str")
	s.NoError(err)
	s.Equal("localhost:3000", str)

	intVal, err := cmd1.Flags().GetInt("int")
	s.NoError(err)
	s.Equal(3000, intVal)

	boolVal, err := cmd1.Flags().GetBool("bool")
	s.NoError(err)
	s.Equal(true, boolVal)

	str, err = cmd1.Flags().GetString("str2")
	s.NoError(err)
	s.Equal("localhost:4000", str)

	intVal, err = cmd1.Flags().GetInt("int2")
	s.NoError(err)
	s.Equal(4000, intVal)

	boolVal, err = cmd1.Flags().GetBool("bool2")
	s.NoError(err)
	s.Equal(false, boolVal)

	s.Equal(s.actualCfgFile, s.file)
}

func (s *ConfigTestSuite) TestInitConfigWithInstance() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "instance")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")
	BindPFlags(flagSet, "group1")

	cmd1.Flags().AddFlagSet(flagSet)

	// Cmd1
	rootCmd.SetArgs([]string{"test1"})
	err := rootCmd.Execute()

	s.NoError(err)
	s.assertFlagValues(cmd1, "localhost:3000 instance", 5000, true)
	s.Equal(s.actualCfgFile, s.file)
}

// This is used by asvec. Instead of having a group like cluster,asadm,aql etc.
// and adding and _{instance} to the group to select config params it uses and
// empty group and uses then instance arg as the group name. Affectively
// allowing the user to define the full group name at runtime.
func (s *ConfigTestSuite) TestInitConfigWithoutGroupsButWithInstance() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "group1")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")
	BindPFlags(flagSet, "")

	cmd1.Flags().AddFlagSet(flagSet)

	// Cmd1
	rootCmd.SetArgs([]string{"test1"})
	err := rootCmd.Execute()

	s.NoError(err)
	s.assertFlagValues(cmd1, "localhost:3000", 3000, true)
	s.Equal(s.actualCfgFile, s.file)
}

func (s *ConfigTestSuite) TestInitConfigWithFlagsOverwrite() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")
	BindPFlags(flagSet, "group1")

	cmd1.Flags().AddFlagSet(flagSet)

	// Cmd1
	rootCmd.SetArgs([]string{"test1", "--str", "overwrite"})
	err := rootCmd.Execute()

	s.NoError(err)

	str, err := cmd1.Flags().GetString("str")
	s.NoError(err)
	s.Equal("overwrite", str)

	intVal, err := cmd1.Flags().GetInt("int")
	s.NoError(err)
	s.Equal(3000, intVal)

	boolVal, err := cmd1.Flags().GetBool("bool")
	s.NoError(err)
	s.Equal(true, boolVal)
}

func (s *ConfigTestSuite) TestInitConfigWithFlagsDefaults() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "DNE")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "foo", "string flag")
	flagSet.Int("int", 99, "int flag")
	flagSet.Bool("bool", true, "bool flag")
	BindPFlags(flagSet, "group1")

	cmd1.Flags().AddFlagSet(flagSet)

	// Cmd1
	rootCmd.SetArgs([]string{"test1"})
	err := rootCmd.Execute()

	s.NoError(err)
	s.assertFlagValues(cmd1, "foo", 99, true)
	s.Equal(s.actualCfgFile, s.file)
}

func (s *ConfigTestSuite) TestInitConfigInstanceFallback() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "instance")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")
	BindPFlagsWithInstanceFallback(flagSet, "group1")

	flagSet2 := &pflag.FlagSet{}
	flagSet2.String("str2", "", "string flag")
	flagSet2.Int("int2", 0, "int flag")
	flagSet2.Bool("bool2", true, "bool flag")
	BindPFlagsWithInstanceFallback(flagSet2, "group2")

	cmd1.Flags().AddFlagSet(flagSet)
	cmd1.Flags().AddFlagSet(flagSet2)

	rootCmd.SetArgs([]string{"test1"})
	s.NoError(rootCmd.Execute())

	// group1_instance exists, so it replaces group1.
	str, err := cmd1.Flags().GetString("str")
	s.NoError(err)
	s.Equal("localhost:3000 instance", str)

	// group2_instance does not exist, so group2 is read.
	str, err = cmd1.Flags().GetString("str2")
	s.NoError(err)
	s.Equal("localhost:4000", str)

	intVal, err := cmd1.Flags().GetInt("int2")
	s.NoError(err)
	s.Equal(4000, intVal)

	boolVal, err := cmd1.Flags().GetBool("bool2")
	s.NoError(err)
	s.False(boolVal)
}

func (s *ConfigTestSuite) TestInitConfigInstanceWithoutFallback() {
	rootCmd, cmd1, _ := s.NewCmds(s.file, "instance")

	flagSet := &pflag.FlagSet{}
	flagSet.String("str2", "default", "string flag")
	BindPFlags(flagSet, "group2")

	cmd1.Flags().AddFlagSet(flagSet)

	rootCmd.SetArgs([]string{"test1"})
	s.NoError(rootCmd.Execute())

	str, err := cmd1.Flags().GetString("str2")
	s.NoError(err)
	s.Equal("default", str)
}

// setupConfigFiles isolates the system config dir, $HOME and the working
// directory, and returns the system and home config file paths.
func setupConfigFiles(t *testing.T) (system, home string) {
	t.Helper()

	Reset()
	t.Cleanup(Reset)

	dir := systemConfDir
	systemConfDir = t.TempDir()

	t.Cleanup(func() { systemConfDir = dir })

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	require.NoError(t, os.Mkdir(filepath.Join(homeDir, ".aerospike"), 0o700))
	t.Chdir(t.TempDir())

	return filepath.Join(systemConfDir, DefaultConfName+".conf"),
		filepath.Join(homeDir, ".aerospike", DefaultConfName+".conf")
}

func writeConfig(t *testing.T, file, text string) string {
	t.Helper()

	require.NoError(t, os.WriteFile(file, []byte(text), 0o600))

	return file
}

func newGroupFlags(t *testing.T, section string, fallback bool, args ...string) *pflag.FlagSet {
	t.Helper()

	flagSet := &pflag.FlagSet{}
	flagSet.String("str", "", "string flag")
	flagSet.Int("int", 0, "int flag")
	flagSet.Bool("bool", false, "bool flag")

	if fallback {
		BindPFlagsWithInstanceFallback(flagSet, section)
	} else {
		BindPFlags(flagSet, section)
	}

	require.NoError(t, flagSet.Parse(args))

	return flagSet
}

func requireGroupFlags(t *testing.T, flagSet *pflag.FlagSet, str string, intVal int, boolVal bool) {
	t.Helper()

	gotStr, err := flagSet.GetString("str")
	require.NoError(t, err)

	gotInt, err := flagSet.GetInt("int")
	require.NoError(t, err)

	gotBool, err := flagSet.GetBool("bool")
	require.NoError(t, err)

	require.Equal(t, []any{str, intVal, boolVal}, []any{gotStr, gotInt, gotBool})
}

func TestInitConfigFilesOrder(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nstr = \"system\"\nint = 1\nbool = true\n")
	writeConfig(t, home, "[group1]\nstr = \"home\"\nint = 2\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nint = 3\n")
	writeConfig(t, DefaultConfName+".conf", "[group1]\nstr = \"working directory\"\n")

	flagSet := newGroupFlags(t, "group1", false, "--bool=false")

	files, err := InitConfigFiles(user, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{system, home, user}, files)
	requireGroupFlags(t, flagSet, "home", 3, false)
}

func TestInitConfigFilesWithoutDefaultFiles(t *testing.T) {
	setupConfigFiles(t)
	writeConfig(t, DefaultConfName+".conf", "[group1]\nstr = \"working directory\"\n")

	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles("", "", flagSet)
	require.NoError(t, err)
	require.Empty(t, files)
	requireGroupFlags(t, flagSet, "", 0, false)

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nint = 3\n")

	Reset()

	flagSet = newGroupFlags(t, "group1", false)

	files, err = InitConfigFiles(user, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{user}, files)
	requireGroupFlags(t, flagSet, "", 3, false)
}

func TestInitConfigFilesErrors(t *testing.T) {
	system, _ := setupConfigFiles(t)

	_, err := InitConfigFiles(filepath.Join(t.TempDir(), "missing.conf"), "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file")
	require.ErrorContains(t, err, "missing.conf")

	writeConfig(t, system, "[group1\n")

	Reset()

	_, err = InitConfigFiles("", "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file "+system)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	stderr := os.Stderr
	os.Stderr = w

	fn()

	os.Stderr = stderr

	require.NoError(t, w.Close())

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	return string(out)
}

func TestInitConfigFilesUnreadableDefaultFileSkipped(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}

	// As in the C tools and asadm: a default file that cannot be read is
	// treated as missing, with a warning. A file the user named still fails.
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nstr = \"system\"\n")
	require.NoError(t, os.Chmod(system, 0))
	writeConfig(t, home, "[group1]\nint = 2\n")

	flagSet := newGroupFlags(t, "group1", false)

	var (
		files []string
		err   error
	)

	stderr := captureStderr(t, func() { files, err = InitConfigFiles("", "", flagSet) })
	require.NoError(t, err)
	require.Equal(t, []string{home}, files)
	requireGroupFlags(t, flagSet, "", 2, false)
	require.Equal(t, "Warning: cannot read config file "+system+": permission denied\n", stderr)

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nint = 3\n")
	require.NoError(t, os.Chmod(user, 0))

	Reset()

	_, err = InitConfigFiles(user, "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file "+user)
}

func TestInitConfigFilesSelectSectionsPerFile(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nstr = \"system\"\n\n[group1_inst]\nstr = \"system inst\"\nint = 1\n")
	writeConfig(t, home, "[group1]\nstr = \"home\"\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
		"[group1]\nint = 2\nbool = false\n\n[group1_inst]\nbool = true\n")

	flagSet := newGroupFlags(t, "group1", true)

	_, err := InitConfigFiles(user, "inst", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "home", 1, true)
}

func TestInitConfigFilesKeepInstanceRulesWithoutFallback(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group2_inst]\nstr = \"system inst\"\n")
	writeConfig(t, home, "[group2]\nstr = \"home\"\nint = 2\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group2_inst]\nint = 4\n")

	flagSet := newGroupFlags(t, "group2", false)

	_, err := InitConfigFiles(user, "inst", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "system inst", 4, false)
}

func TestInitConfigFilesUnknownKeysPerFile(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nbogus = 1\n\n[group1_inst]\nstr = \"system inst\"\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nstr = \"user\"\n")

	_, err := InitConfigFiles(user, "inst", newGroupFlags(t, "group1", true))
	require.NoError(t, err)

	writeConfig(t, home, "[group1_inst]\nbogus = 1\n")

	Reset()

	_, err = InitConfigFiles(user, "inst", newGroupFlags(t, "group1", true))
	require.EqualError(t, err, "config file "+home+": unknown key bogus in the [group1_inst] config section")
}

func TestInitConfigDefaultPathUnchanged(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nint = 1\n")
	writeConfig(t, home, "[group1]\nbool = true\n")
	working := writeConfig(t, DefaultConfName+".conf", "[group1]\nstr = \"working directory\"\n")

	flagSet := newGroupFlags(t, "group1", true)

	file, err := InitConfig("", "", flagSet)
	require.NoError(t, err)
	require.Equal(t, working, filepath.Base(file))
	requireGroupFlags(t, flagSet, "working directory", 0, false)

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1_inst]\nint = 3\n")

	Reset()

	flagSet = newGroupFlags(t, "group1", true)

	file, err = InitConfig(user, "inst", flagSet)
	require.NoError(t, err)
	require.Equal(t, user, file)
	requireGroupFlags(t, flagSet, "", 3, false)
}

func TestRunConfigTestSuite(t *testing.T) {
	files := []struct {
		file    string
		fileTxt string
	}{
		{
			"basic.conf",
			tomlConfigTxt,
		},
		{
			"basic.yaml",
			yamlConfigTxt,
		},
	}

	for _, file := range files {
		cts := new(ConfigTestSuite)
		cts.file = file.file
		cts.fileTxt = file.fileTxt
		suite.Run(t, cts)
	}
}
