package config

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
