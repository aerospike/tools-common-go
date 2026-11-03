package config

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

	dir, dirs := systemConfDir, confDirs
	systemConfDir = t.TempDir()
	confDirs = []string{".", systemConfDir}

	t.Cleanup(func() { systemConfDir, confDirs = dir, dirs })

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

	files, err := InitConfigFiles(Files{File: user}, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{system, home, user}, files)
	requireGroupFlags(t, flagSet, "home", 3, false)
}

func TestInitConfigFilesWithoutDefaultFiles(t *testing.T) {
	setupConfigFiles(t)
	writeConfig(t, DefaultConfName+".conf", "[group1]\nstr = \"working directory\"\n")

	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{}, "", flagSet)
	require.NoError(t, err)
	require.Empty(t, files)
	requireGroupFlags(t, flagSet, "", 0, false)

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nint = 3\n")

	Reset()

	flagSet = newGroupFlags(t, "group1", false)

	files, err = InitConfigFiles(Files{File: user}, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{user}, files)
	requireGroupFlags(t, flagSet, "", 3, false)
}

func TestInitConfigFilesErrors(t *testing.T) {
	system, _ := setupConfigFiles(t)

	missing := filepath.Join(t.TempDir(), "missing.conf")

	_, err := InitConfigFiles(Files{File: missing}, "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file")
	require.ErrorContains(t, err, "missing.conf")

	writeConfig(t, system, "[group1\n")

	Reset()

	_, err = InitConfigFiles(Files{}, "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file "+system)
}

func TestInitConfigFilesOnlyFile(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nstr = \"system\"\n")
	writeConfig(t, home, "[group1]\nstr = \"home\"\n")

	dir := t.TempDir()
	included := writeConfig(t, filepath.Join(dir, "included.conf"), "[group1]\nbool = true\n")
	only := writeConfig(t, filepath.Join(dir, "only.conf"), "[include]\nfile = \""+included+"\"\n\n[group1]\nint = 3\n")
	user := writeConfig(t, filepath.Join(dir, "user.conf"), "[group1]\nstr = \"user\"\n")

	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{File: user, Only: only}, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{only, included}, files)
	requireGroupFlags(t, flagSet, "", 3, true)
}

func TestInitConfigFilesOnlyFileMissing(t *testing.T) {
	setupConfigFiles(t)

	missing := filepath.Join(t.TempDir(), "missing.conf")

	_, err := InitConfigFiles(Files{Only: missing}, "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file "+missing)
}

func TestInitConfigFilesNoFile(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1\n")
	writeConfig(t, home, "[group1\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1\n")

	flagSet := newGroupFlags(t, "group1", false, "--int=4")

	files, err := InitConfigFiles(Files{File: user, None: true}, "", flagSet)
	require.NoError(t, err)
	require.Empty(t, files)
	requireGroupFlags(t, flagSet, "", 4, false)
}

func TestInitConfigFilesNoFileWithOnlyFile(t *testing.T) {
	setupConfigFiles(t)

	only := writeConfig(t, filepath.Join(t.TempDir(), "only.conf"), "[group1]\nint = 3\n")
	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{Only: only, None: true}, "", flagSet)
	require.EqualError(t, err,
		"--no-config-file and only-config-file are mutually exclusive option. Please enable only one.")
	require.Empty(t, files)
	requireGroupFlags(t, flagSet, "", 0, false)
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

	stderr := captureStderr(t, func() { files, err = InitConfigFiles(Files{}, "", flagSet) })
	require.NoError(t, err)
	require.Equal(t, []string{home}, files)
	requireGroupFlags(t, flagSet, "", 2, false)
	require.Equal(t, "Warning: cannot read config file "+system+": Permission denied\n", stderr)

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nint = 3\n")
	require.NoError(t, os.Chmod(user, 0))

	Reset()

	_, err = InitConfigFiles(Files{File: user}, "", newGroupFlags(t, "group1", false))
	require.ErrorContains(t, err, "failed to read config file "+user)
}

func TestInitConfigFilesUnopenableFilesSkipped(t *testing.T) {
	// As in the C tools: a default or included file that cannot be opened for
	// any reason but being missing is skipped with a warning.
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nint = 1\n")

	require.NoError(t, os.Remove(filepath.Dir(home)))
	writeConfig(t, filepath.Dir(home), "")

	loop := filepath.Join(t.TempDir(), "loop.conf")
	require.NoError(t, os.Symlink(loop, loop))

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), fmt.Sprintf("[include]\nfile = %q\n", loop))
	flagSet := newGroupFlags(t, "group1", false)

	var (
		files []string
		err   error
	)

	stderr := captureStderr(t, func() { files, err = InitConfigFiles(Files{File: user}, "", flagSet) })
	require.NoError(t, err)
	require.Equal(t, []string{system, user}, files)
	requireGroupFlags(t, flagSet, "", 1, false)
	require.Equal(t, "Warning: cannot read config file "+home+": Not a directory\n"+
		"Warning: cannot read config file "+loop+": Too many levels of symbolic links\n", stderr)
}

func TestInitConfigFilesSelectSectionsPerFile(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nstr = \"system\"\n\n[group1_inst]\nstr = \"system inst\"\nint = 1\n")
	writeConfig(t, home, "[group1]\nstr = \"home\"\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
		"[group1]\nint = 2\nbool = false\n\n[group1_inst]\nbool = true\n")

	flagSet := newGroupFlags(t, "group1", true)

	_, err := InitConfigFiles(Files{File: user}, "inst", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "home", 1, true)
}

func TestInitConfigFilesKeepInstanceRulesWithoutFallback(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group2_inst]\nstr = \"system inst\"\n")
	writeConfig(t, home, "[group2]\nstr = \"home\"\nint = 2\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group2_inst]\nint = 4\n")

	flagSet := newGroupFlags(t, "group2", false)

	_, err := InitConfigFiles(Files{File: user}, "inst", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "system inst", 4, false)
}

func TestInitConfigFilesUnknownKeysPerFile(t *testing.T) {
	system, home := setupConfigFiles(t)
	writeConfig(t, system, "[group1]\nbogus = 1\n\n[group1_inst]\nstr = \"system inst\"\n")
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[group1]\nstr = \"user\"\n")

	_, err := InitConfigFiles(Files{File: user}, "inst", newGroupFlags(t, "group1", true))
	require.NoError(t, err)

	writeConfig(t, home, "[group1_inst]\nbogus = 1\n")

	Reset()

	_, err = InitConfigFiles(Files{File: user}, "inst", newGroupFlags(t, "group1", true))
	require.EqualError(t, err, "config file "+home+": unknown key bogus in the [group1_inst] config section")
}

func TestInitConfigFilesInstanceSectionMustBeTable(t *testing.T) {
	// As in asbackup and aql, an instance value that is not a table falls back
	// to the default section.
	for name, conf := range map[string]string{
		"string":          "group1_inst = \"x\"\n\n[group1]\nstr = \"base\"\n",
		"array of tables": "[group1]\nstr = \"base\"\n\n[[group1_inst]]\nstr = \"array\"\n",
	} {
		for loader, load := range loaders {
			t.Run(name+" "+loader, func(t *testing.T) {
				setupConfigFiles(t)
				user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), conf)
				flagSet := newGroupFlags(t, "group1", true)

				require.NoError(t, load(user, "inst", flagSet))
				requireGroupFlags(t, flagSet, "base", 0, false)
			})
		}
	}
}

var loaders = map[string]func(file, instance string, flags *pflag.FlagSet) error{
	"InitConfigFiles": func(file, instance string, flags *pflag.FlagSet) error {
		_, err := InitConfigFiles(Files{File: file}, instance, flags)
		return err
	},
	"InitConfig": func(file, instance string, flags *pflag.FlagSet) error {
		_, err := InitConfig(file, instance, flags)
		return err
	},
}

func TestInitConfigFilesSectionNameCase(t *testing.T) {
	// The C tools match section names exactly, so a section that matches only
	// when case is ignored is an error rather than read.
	tests := map[string]struct {
		conf     string
		instance string
		want     string
	}{
		"instance section": {
			conf:     "[group1]\nstr = \"base\"\n\n[group1_INST]\nstr = \"upper\"\n",
			instance: "inst",
			want:     "the [group1_INST] config section differs from [group1_inst] only in case",
		},
		"default section": {
			conf: "[GROUP1]\nstr = \"upper\"\n",
			want: "the [GROUP1] config section differs from [group1] only in case",
		},
		"both spellings": {
			conf:     "[group1_inst]\nstr = \"lower\"\n\n[group1_Inst]\nint = 1\n",
			instance: "inst",
			want:     "the [group1_Inst] config section differs from [group1_inst] only in case",
		},
	}

	for name, tt := range tests {
		for loader, load := range loaders {
			t.Run(name+" "+loader, func(t *testing.T) {
				setupConfigFiles(t)
				user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), tt.conf)

				err := load(user, tt.instance, newGroupFlags(t, "group1", true))
				require.EqualError(t, err, "config file "+user+": "+tt.want)
			})
		}
	}

	const (
		upper = "[GROUP1]\nstr = \"upper\"\n"
		want  = ": the [GROUP1] config section differs from [group1] only in case"
	)

	t.Run("included file", func(t *testing.T) {
		setupConfigFiles(t)
		include := writeConfig(t, filepath.Join(t.TempDir(), "include.conf"), upper)
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), fmt.Sprintf("[include]\nfile = %q\n", include))

		_, err := InitConfigFiles(Files{File: user}, "", newGroupFlags(t, "group1", true))
		require.EqualError(t, err, "config file "+include+want)
	})

	t.Run("toml file", func(t *testing.T) {
		setupConfigFiles(t)
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.toml"), upper)

		_, err := InitConfig(user, "", newGroupFlags(t, "group1", true))
		require.EqualError(t, err, "config file "+user+want)
	})

	for _, name := range []string{DefaultConfName + ".toml", DefaultConfName + ".conf"} {
		t.Run("default search "+name, func(t *testing.T) {
			setupConfigFiles(t)
			writeConfig(t, name, upper)

			_, err := InitConfig("", "", newGroupFlags(t, "group1", true))
			require.Error(t, err)
			require.Regexp(t, `^config file \S*`+regexp.QuoteMeta(name+want)+`$`, err.Error())
		})
	}

	setupConfigFiles(t)
	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
		"[group1]\nint = 1\n\n[group1_INST]\nstr = \"upper\"\n")
	flagSet := newGroupFlags(t, "group1", true)

	_, err := InitConfigFiles(Files{File: user}, "INST", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "upper", 0, false)
}

func TestInitConfigFilesReadsEveryFileAsTOML(t *testing.T) {
	for _, name := range []string{"astools", "user.yaml", "user.json"} {
		t.Run(name, func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), name), "[group1]\nstr = \"toml\"\n")
			flagSet := newGroupFlags(t, "group1", false)

			files, err := InitConfigFiles(Files{File: user}, "", flagSet)
			require.NoError(t, err)
			require.Equal(t, []string{user}, files)
			requireGroupFlags(t, flagSet, "toml", 0, false)
		})
	}
}

func TestInitConfigFilesInclude(t *testing.T) {
	system, home := setupConfigFiles(t)
	dir := t.TempDir()

	homeInclude := writeConfig(t, filepath.Join(dir, "home-include.conf"), "[group1]\nint = 5\nbool = true\n")
	userInclude := writeConfig(t, filepath.Join(dir, "user-include.conf"), "[group1]\nint = 2\n")

	writeConfig(t, system, "[group1]\nstr = \"system\"\n")
	writeConfig(t, home, fmt.Sprintf("[include]\nfile = %q\n\n[group1]\nstr = \"home\"\nint = 4\n", homeInclude))
	user := writeConfig(t, filepath.Join(dir, "user.conf"),
		fmt.Sprintf("[group1]\nint = 1\n\n[include]\nfile = %q\n", userInclude))

	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{File: user}, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{system, home, homeInclude, user, userInclude}, files)
	requireGroupFlags(t, flagSet, "home", 2, true)
}

func TestInitConfigFilesIncludeDirectory(t *testing.T) {
	setupConfigFiles(t)

	dir := t.TempDir()
	include := filepath.Join(dir, "include")
	require.NoError(t, os.MkdirAll(filepath.Join(include, "sub"), 0o700))

	a := writeConfig(t, filepath.Join(include, "a.conf"), "[group1]\nint = 1\nstr = \"a\"\n")
	b := writeConfig(t, filepath.Join(include, "b"), "[group1]\nint = 2\n")
	sub := writeConfig(t, filepath.Join(include, "sub", "c.conf"), "[group1]\nbool = true\n")

	outside := t.TempDir()
	linked := writeConfig(t, filepath.Join(outside, "linked.conf"), "[group1]\nstr = \"linked\"\n")
	writeConfig(t, filepath.Join(outside, "skipped.conf"), "[group1]\nint = 9\n")
	require.NoError(t, os.Symlink(linked, filepath.Join(include, "d.conf")))
	require.NoError(t, os.Symlink(outside, filepath.Join(include, "e")))

	user := writeConfig(t, filepath.Join(dir, "user.conf"), fmt.Sprintf("[include]\ndirectory = %q\n", include))
	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{File: user}, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{user, a, b, filepath.Join(include, "d.conf"), sub}, files)
	requireGroupFlags(t, flagSet, "linked", 2, true)
}

func TestInitConfigFilesIncludeDirectoryBrokenLinks(t *testing.T) {
	setupConfigFiles(t)

	include := t.TempDir()
	dangling := filepath.Join(include, "dangling.conf")
	loop := filepath.Join(include, "loop.conf")
	require.NoError(t, os.Symlink(filepath.Join(include, "missing"), dangling))
	require.NoError(t, os.Symlink(loop, loop))
	a := writeConfig(t, filepath.Join(include, "a.conf"), "[group1]\nint = 1\n")

	user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), fmt.Sprintf("[include]\ndirectory = %q\n", include))
	flagSet := newGroupFlags(t, "group1", false)

	var (
		files []string
		err   error
	)

	stderr := captureStderr(t, func() { files, err = InitConfigFiles(Files{File: user}, "", flagSet) })
	require.NoError(t, err)
	require.Equal(t, []string{user, a}, files)
	requireGroupFlags(t, flagSet, "", 1, false)
	require.Equal(t, "Warning: cannot read config file "+dangling+": No such file or directory\n"+
		"Warning: cannot read config file "+loop+": Too many levels of symbolic links\n", stderr)
}

func TestInitConfigFilesDottedInstance(t *testing.T) {
	const conf = "[group1]\nstr = \"base\"\n\n[\"group1_a.b\"]\nstr = \"dotted\"\nint = 2\n"

	for loader, load := range loaders {
		t.Run(loader, func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), conf)
			flagSet := newGroupFlags(t, "group1", true)

			require.NoError(t, load(user, "a.b", flagSet))
			requireGroupFlags(t, flagSet, "dotted", 2, false)
		})

		t.Run(loader+" unknown key", func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), conf+"bogus = 1\n")

			err := load(user, "a.b", newGroupFlags(t, "group1", true))
			require.ErrorContains(t, err, "unknown key bogus in the [group1_a.b] config section")
		})
	}

	t.Run("unknown key in a file without the instance section", func(t *testing.T) {
		system, _ := setupConfigFiles(t)
		writeConfig(t, system, "[group1]\nbogus = 1\n")
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), conf)

		_, err := InitConfigFiles(Files{File: user}, "a.b", newGroupFlags(t, "group1", true))
		require.EqualError(t, err, "config file "+system+": unknown key bogus in the [group1] config section")
	})

	for loader, load := range loaders {
		t.Run(loader+" unknown key next to the section of another instance", func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
				"[group1]\nbogus = 1\n\n[\"group1_a.b\"]\nstr = \"dotted\"\n")

			err := load(user, "a", newGroupFlags(t, "group1", true))
			require.ErrorContains(t, err, "unknown key bogus in the [group1] config section")
		})
	}

	t.Run("unknown key in another file than the section of another instance", func(t *testing.T) {
		system, _ := setupConfigFiles(t)
		writeConfig(t, system, "[group1]\nbogus = 1\n")
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), conf)

		_, err := InitConfigFiles(Files{File: user}, "a", newGroupFlags(t, "group1", true))
		require.EqualError(t, err, "config file "+system+": unknown key bogus in the [group1] config section")
	})
}

func TestInitConfigFilesUnquotedDottedInstance(t *testing.T) {
	// An unquoted [group1_a.b] is table b in table group1_a. The C tools look up
	// the whole name as a root key, so they do not read it for instance a.b.
	for name, tt := range map[string]struct{ conf, instance string }{
		"nested header":          {"[group1]\nstr = \"base\"\n\n[group1_a.b]\nstr = \"nested\"\n", "a.b"},
		"inline table":           {"group1_a = { b = { str = \"nested\" } }\n\n[group1]\nstr = \"base\"\n", "a.b"},
		"header in another case": {"[group1]\nstr = \"base\"\n\n[Group1_a.b]\nstr = \"nested\"\n", "a.b"},
		"partly quoted header":   {"[group1]\nstr = \"base\"\n\n[\"group1_a.b\".c]\nstr = \"nested\"\n", "a.b.c"},
	} {
		want := fmt.Sprintf(`the [group1_%s] config section must be quoted as ["group1_%[1]s"]`, tt.instance)

		for loader, load := range loaders {
			t.Run(name+" "+loader, func(t *testing.T) {
				setupConfigFiles(t)
				user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), tt.conf)

				err := load(user, tt.instance, newGroupFlags(t, "group1", true))
				require.EqualError(t, err, "config file "+user+": "+want)
			})
		}
	}

	for name, tt := range map[string]struct{ file, conf string }{
		"YAML nested":  {"user.yaml", "group1:\n  str: base\ngroup1_a:\n  b:\n    str: nested\n"},
		"YAML literal": {"user.yaml", "group1:\n  str: base\ngroup1_a.b:\n  str: literal\n"},
		"JSON nested":  {"user.json", `{"group1": {"str": "base"}, "group1_a": {"b": {"str": "nested"}}}`},
	} {
		t.Run(name+" InitConfig", func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), tt.file), tt.conf)

			_, err := InitConfig(user, "a.b", newGroupFlags(t, "group1", true))
			require.EqualError(t, err,
				"config file "+user+": the [group1_a.b] config section needs a .conf or .toml config file")
		})
	}

	t.Run("YAML without the section InitConfig", func(t *testing.T) {
		setupConfigFiles(t)
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.yaml"), "group1:\n  str: base\n")
		flagSet := newGroupFlags(t, "group1", true)

		_, err := InitConfig(user, "a.b", flagSet)
		require.NoError(t, err)
		requireGroupFlags(t, flagSet, "base", 0, false)
	})

	for loader, load := range loaders {
		t.Run("quoted header next to a nested one "+loader, func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
				"[group1]\nstr = \"base\"\n\n[\"group1_a.b\"]\nstr = \"quoted\"\n\n[group1_a.b]\nstr = \"nested\"\n")
			flagSet := newGroupFlags(t, "group1", true)

			require.NoError(t, load(user, "a.b", flagSet))
			requireGroupFlags(t, flagSet, "quoted", 0, false)
		})
	}
}

func TestInitConfigFilesIncludeFileBeforeDirectory(t *testing.T) {
	setupConfigFiles(t)

	dir := t.TempDir()
	include := filepath.Join(dir, "include")
	require.NoError(t, os.Mkdir(include, 0o700))

	file := writeConfig(t, filepath.Join(dir, "file.conf"), "[group1]\nint = 1\nstr = \"file\"\n")
	inDir := writeConfig(t, filepath.Join(include, "a.conf"), "[group1]\nint = 2\n")
	user := writeConfig(t, filepath.Join(dir, "user.conf"),
		fmt.Sprintf("[include]\ndirectory = %q\nfile = %q\n", include, file))
	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{File: user}, "", flagSet)
	require.NoError(t, err)
	require.Equal(t, []string{user, file, inDir}, files)
	requireGroupFlags(t, flagSet, "file", 2, false)
}

func TestInitConfigFilesIncludeDepth(t *testing.T) {
	setupConfigFiles(t)

	dir := t.TempDir()
	chain := []string{"user.conf", "1.conf", "2.conf", "3.conf", "4.conf"}

	write := func(n int) {
		for i := range n {
			text := fmt.Sprintf("[group1]\nint = %d\n", i)
			if i+1 < n {
				text += fmt.Sprintf("\n[include]\nfile = %q\n", filepath.Join(dir, chain[i+1]))
			}

			writeConfig(t, filepath.Join(dir, chain[i]), text)
		}
	}

	write(4)

	flagSet := newGroupFlags(t, "group1", false)

	files, err := InitConfigFiles(Files{File: filepath.Join(dir, chain[0])}, "", flagSet)
	require.NoError(t, err)
	require.Len(t, files, 4)
	requireGroupFlags(t, flagSet, "", 3, false)

	write(5)
	Reset()

	_, err = InitConfigFiles(Files{File: filepath.Join(dir, chain[0])}, "", newGroupFlags(t, "group1", false))
	require.EqualError(t, err, "config file "+filepath.Join(dir, "4.conf")+": [include] is nested more than 3 levels deep")
}

func TestInitConfigFilesIncludeErrors(t *testing.T) {
	dir := t.TempDir()
	notTOML := writeConfig(t, filepath.Join(dir, "not-toml"), "[group1\n")
	badDir := filepath.Join(dir, "bad-dir")
	require.NoError(t, os.Mkdir(badDir, 0o700))
	writeConfig(t, filepath.Join(badDir, "a.conf"), "[group1\n")

	tests := map[string]struct {
		include string
		want    string
	}{
		"unknown key": {
			include: "files = \"x\"\n",
			want:    "unknown key files in the [include] config section",
		},
		"not a string": {
			include: "file = 1\n",
			want:    `invalid value "1" for file in the [include] config section, expected a path`,
		},
		"missing directory": {
			include: fmt.Sprintf("directory = %q\n", filepath.Join(dir, "missing")),
			want:    "cannot read config directory " + filepath.Join(dir, "missing") + ": No such file or directory",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), "[include]\n"+tt.include)

			_, err := InitConfigFiles(Files{File: user}, "", newGroupFlags(t, "group1", false))
			require.EqualError(t, err, "config file "+user+": "+tt.want)
		})
	}

	for name, include := range map[string]string{"file": notTOML, "directory": badDir} {
		t.Run("parse error in an included "+name, func(t *testing.T) {
			setupConfigFiles(t)
			user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
				fmt.Sprintf("[include]\n%s = %q\n", name, include))

			_, err := InitConfigFiles(Files{File: user}, "", newGroupFlags(t, "group1", false))
			require.ErrorContains(t, err, "failed to read config file ")
		})
	}

	// Unlike the C tools, which skip a bad entry of an included directory, any
	// error there fails the load, since the entry may hold the agent CA.
	t.Run("directory holding its includer", func(t *testing.T) {
		setupConfigFiles(t)
		self := t.TempDir()
		user := writeConfig(t, filepath.Join(self, "user.conf"), fmt.Sprintf("[include]\ndirectory = %q\n", self))

		_, err := InitConfigFiles(Files{File: user}, "", newGroupFlags(t, "group1", false))
		require.ErrorContains(t, err, "[include] is nested more than 3 levels deep")
	})

	t.Run("unreadable subdirectory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read any directory")
		}

		setupConfigFiles(t)
		include := t.TempDir()
		sub := filepath.Join(include, "sub")
		require.NoError(t, os.Mkdir(sub, 0))
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"), fmt.Sprintf("[include]\ndirectory = %q\n", include))

		_, err := InitConfigFiles(Files{File: user}, "", newGroupFlags(t, "group1", false))
		require.EqualError(t, err, "config file "+user+": cannot read config directory "+sub+": Permission denied")
	})

	t.Run("missing file is skipped", func(t *testing.T) {
		setupConfigFiles(t)
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
			fmt.Sprintf("[group1]\nint = 1\n\n[include]\nfile = %q\n", filepath.Join(dir, "missing.conf")))
		flagSet := newGroupFlags(t, "group1", false)

		files, err := InitConfigFiles(Files{File: user}, "", flagSet)
		require.NoError(t, err)
		require.Equal(t, []string{user}, files)
		requireGroupFlags(t, flagSet, "", 1, false)
	})

	t.Run("unreadable file is skipped with a warning", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read any file")
		}

		setupConfigFiles(t)
		unreadable := writeConfig(t, filepath.Join(t.TempDir(), "unreadable.conf"), "[group1]\nint = 2\n")
		require.NoError(t, os.Chmod(unreadable, 0))
		user := writeConfig(t, filepath.Join(t.TempDir(), "user.conf"),
			fmt.Sprintf("[group1]\nint = 1\n\n[include]\nfile = %q\n", unreadable))
		flagSet := newGroupFlags(t, "group1", false)

		var (
			files []string
			err   error
		)

		stderr := captureStderr(t, func() { files, err = InitConfigFiles(Files{File: user}, "", flagSet) })
		require.NoError(t, err)
		require.Equal(t, []string{user}, files)
		requireGroupFlags(t, flagSet, "", 1, false)
		require.Equal(t, "Warning: cannot read config file "+unreadable+": Permission denied\n", stderr)
	})
}

func TestInitConfigFilesIncludeSelectsSectionsPerFile(t *testing.T) {
	setupConfigFiles(t)

	dir := t.TempDir()
	include := writeConfig(t, filepath.Join(dir, "include.conf"),
		"[group1]\nint = 2\n\n[group1_other]\nint = 9\n")
	user := writeConfig(t, filepath.Join(dir, "user.conf"),
		fmt.Sprintf("[group1_inst]\nstr = \"inst\"\n\n[include]\nfile = %q\n", include))
	flagSet := newGroupFlags(t, "group1", true)

	_, err := InitConfigFiles(Files{File: user}, "inst", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "inst", 2, false)
}

func TestInitConfigIgnoresInclude(t *testing.T) {
	setupConfigFiles(t)

	dir := t.TempDir()
	include := writeConfig(t, filepath.Join(dir, "include.conf"), "[group1]\nint = 2\n")
	user := writeConfig(t, filepath.Join(dir, "user.conf"),
		fmt.Sprintf("[group1]\nint = 1\n\n[include]\nfile = %q\ndirectory = \"/missing\"\n", include))
	flagSet := newGroupFlags(t, "group1", false)

	_, err := InitConfig(user, "", flagSet)
	require.NoError(t, err)
	requireGroupFlags(t, flagSet, "", 1, false)
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
