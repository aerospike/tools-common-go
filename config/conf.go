package config

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// A map that maps config keys i.e. "cluster.host" to flag names i.e. "host".
// This is only needed because if "instance". Otherwise we would just run
// RegisterAlias inside the BindPFlags function.
var configToFlagMap = map[string]string{}

// Sections whose <section>_<instance> falls back to <section> when absent.
var fallbackSections = map[string]bool{}
var confDirs = []string{".", DefaultConfDir}
var confName = DefaultConfName

// SetConfDirs sets the directories to search for the config file when a file
// name is not explicitly provided. If a file name is explicitly provided viper
// checks both relative and absolute file paths.
func SetDefaultConfDirs(dirs []string) {
	confDirs = dirs
}

// SetConfName sets the name of the config file to search for. For aerospike
// tools this is astools but for asvec it is asvec.
func SetDefaultConfName(name string) {
	confName = name
}

// InitConfig reads in config file and ENV variables if set. Should be called
// from the root commands PersistentPreRunE function with the flags of the current command.
func InitConfig(userProvidedCfgFile, instance string, flags *pflag.FlagSet) (string, error) {
	if userProvidedCfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(userProvidedCfgFile)

		if strings.HasSuffix(userProvidedCfgFile, ".conf") {
			// If .conf then explicitly set type to toml.
			viper.SetConfigType("toml")
		}
	} else {
		for _, d := range confDirs {
			viper.AddConfigPath(d)
		}

		viper.SetConfigName(confName)
	}

	if err := viper.ReadInConfig(); err != nil {
		if userProvidedCfgFile != "" {
			// User provided specific file, so we should return an error no
			// matter what.
			return "", fmt.Errorf("failed to read config file: %w", err)
		} else if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// We are relying on the default config file destination. If the
			// file is not found don't consider it an error.
			viper.SetConfigName(confName + ".conf")
			viper.SetConfigType("toml")

			if err = viper.ReadInConfig(); err != nil {
				return "", nil
			}
		} else {
			return "", fmt.Errorf("failed to read config file: %w", err)
		}
	}

	return viper.ConfigFileUsed(), SetFlags(instance, flags)
}

// Directory of the system-wide file InitConfigFiles reads.
var systemConfDir = DefaultConfDir

// InitConfigFiles is InitConfig with the config file loading of the Aerospike
// C tools. It reads /etc/aerospike/<name>.conf, then
// $HOME/.aerospike/<name>.conf, then userProvidedCfgFile when given, and never
// <name>.conf in the working directory. A missing default file is skipped.
// Values merge key by key, a later file wins, and the command line wins over
// all files. A section bound with BindPFlagsWithInstanceFallback is selected in
// each file before the merge. It returns the files read, in order.
func InitConfigFiles(userProvidedCfgFile, instance string, flags *pflag.FlagSet) ([]string, error) {
	paths := []string{filepath.Join(systemConfDir, confName+".conf")}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".aerospike", confName+".conf"))
	}

	defaults := len(paths)

	if userProvidedCfgFile != "" {
		paths = append(paths, userProvidedCfgFile)
	}

	var (
		used  []string
		files []*viper.Viper
	)

	for i, path := range paths {
		file := viper.New()
		file.SetConfigFile(path)

		if strings.HasSuffix(path, ".conf") {
			file.SetConfigType("toml")
		}

		if err := file.ReadInConfig(); err != nil {
			if i < defaults && errors.Is(err, fs.ErrNotExist) {
				continue
			}

			// As in the C tools and asadm, an unreadable default file is read as
			// missing. A file the user named still fails.
			if i < defaults && errors.Is(err, fs.ErrPermission) {
				fmt.Fprintf(os.Stderr, "Warning: cannot read config file %s: permission denied\n", path)
				continue
			}

			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}

		if err := viper.MergeConfigMap(selectSections(file, instance)); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
		}

		used = append(used, path)
		files = append(files, file)
	}

	return used, setFlags(instance, flags, files)
}

// selectSections returns the settings of file with each section bound with
// BindPFlagsWithInstanceFallback replaced by the one selected in that file.
func selectSections(file *viper.Viper, instance string) map[string]any {
	settings := file.AllSettings()

	for base := range fallbackSections {
		if section := fallbackSection(file, base, instance); section != base {
			// A copy: viper keeps the merged map, and a later file's merge must
			// not write into this file's own section.
			settings[base] = maps.Clone(file.GetStringMap(section))
			delete(settings, strings.ToLower(section))
		}
	}

	return settings
}

func fallbackSection(v *viper.Viper, base, instance string) string {
	if section := base + "_" + instance; instance != "" && v.IsSet(section) {
		return section
	}

	return base
}

// configSetter is a flag value that SetFlags passes its config file value as
// read, with the section name, in place of Set, even when the flag was given
// on the command line.
type configSetter interface {
	SetConfig(section string, value any) error
}

// configFileSetter is a configSetter that InitConfigFiles tells, before the
// SetConfig calls of each config file, the position of that file.
type configFileSetter interface {
	SetConfigFile(index int)
}

func SetFlags(instance string, flags *pflag.FlagSet) error {
	return setFlags(instance, flags, nil)
}

// setFlags is SetFlags. With files, the config files InitConfigFiles read in
// order, configSetter flags and unknown keys are handled one file at a time.
func setFlags(instance string, flags *pflag.FlagSet, files []*viper.Viper) error {
	var persistedErr error

	strictKeys := map[string]map[string]bool{}

	flags.VisitAll(func(f *pflag.Flag) {
		// Convert "host" into "cluster_<instance>.host"
		alias := getAlias(f.Name, instance)

		// Could be done in BindPFlags if not for "instance". Without this
		// we would need to do viper.GetString("cluster.host") instead of
		// viper.GetString("host").
		viper.RegisterAlias(f.Name, alias)

		// We must bind the flags for GetString to return flags as well as
		// config file values.
		err := viper.BindPFlag(alias, f)
		if err != nil {
			persistedErr = fmt.Errorf("failed to bind flag %s: %s", f.Name, err)
			return
		}

		section, key, nested := strings.Cut(alias, ".")
		if base, _, _ := strings.Cut(configToFlagMap[f.Name], "."); nested && fallbackSections[base] {
			if strictKeys[section] == nil {
				strictKeys[section] = map[string]bool{}
			}

			strictKeys[section][key] = true
		}

		if setter, ok := f.Value.(configSetter); ok && nested {
			if value, found := viper.GetStringMap(section)[key]; found && files == nil {
				if err := setter.SetConfig(section, value); err != nil {
					persistedErr = err
				}
			}

			return
		}

		val := viper.GetString(f.Name)

		// Apply the viper config value to the flag when viper has a value
		if viper.IsSet(f.Name) && !f.Changed {
			if err := f.Value.Set(val); err != nil {
				persistedErr = fmt.Errorf("failed to parse flag %s: %s", f.Name, err)
			}
		}
	})

	for i, file := range files {
		if err := setConfigFile(i, file, instance, flags, strictKeys); err != nil {
			return fmt.Errorf("config file %s: %w", file.ConfigFileUsed(), err)
		}
	}

	if files == nil {
		for section, known := range strictKeys {
			if err := checkKeys(viper.GetViper(), section, known); err != nil {
				return err
			}
		}
	}

	return persistedErr
}

// setConfigFile passes the values of one config file to the configSetter
// flags and checks the sections it selects for unknown keys.
func setConfigFile(index int, file *viper.Viper, instance string, flags *pflag.FlagSet,
	strictKeys map[string]map[string]bool,
) error {
	var persistedErr error

	flags.VisitAll(func(f *pflag.Flag) {
		setter, ok := f.Value.(configSetter)
		section, key, nested := strings.Cut(aliasIn(file, f.Name, instance), ".")

		if !ok || !nested {
			return
		}

		if fileSetter, ok := setter.(configFileSetter); ok {
			fileSetter.SetConfigFile(index)
		}

		if value, found := file.GetStringMap(section)[key]; found {
			if err := setter.SetConfig(section, value); err != nil {
				persistedErr = err
			}
		}
	})

	for base, known := range strictKeys {
		if err := checkKeys(file, fallbackSection(file, base, instance), known); err != nil {
			return err
		}
	}

	return persistedErr
}

func checkKeys(v *viper.Viper, section string, known map[string]bool) error {
	for _, key := range slices.Sorted(maps.Keys(v.GetStringMap(section))) {
		if !known[key] {
			return fmt.Errorf("unknown key %s in the [%s] config section", key, section)
		}
	}

	return nil
}

// BindPFlags binds the flags to viper. Should be called after the flag set is
// created. The section is prepended to the flag name to create the viper key.
// For example, if the config is found under the "cluster" section then we will
// bind "cluster.host" to the flag "host". If the section is empty then the flag
// name is used as the key.
func BindPFlags(flags *pflag.FlagSet, section string) {
	if section != "" {
		section += "."
	}

	flags.VisitAll(func(f *pflag.Flag) {
		// We need this to handle the "instance" flag. We will Bind the flags later
		configToFlagMap[f.Name] = section + f.Name
	})
}

// BindPFlagsWithInstanceFallback is like BindPFlags, except that with an
// instance it reads <section>_<instance> when that section exists and <section>
// otherwise. This matches how the Aerospike C tools read [secret-agent]. A key
// in the section read that is not one of the flags is an error.
func BindPFlagsWithInstanceFallback(flags *pflag.FlagSet, section string) {
	BindPFlags(flags, section)

	fallbackSections[section] = true
}

// Reset resets the global configToFlagMap and viper instance.
// Should be called before or after tests that use InitConfig or BindPFlags.
// If using testify suites call it in the SetupTest function and or
// SetupSubTests if using suite.T().Run(...).
func Reset() {
	configToFlagMap = map[string]string{}
	fallbackSections = map[string]bool{}

	viper.Reset()
}

func getAlias(key, instance string) string {
	return aliasIn(viper.GetViper(), key, instance)
}

func aliasIn(v *viper.Viper, key, instance string) string {
	if k, ok := configToFlagMap[key]; ok {
		key = k
	}

	keySplit := strings.SplitN(key, ".", 2)

	if len(keySplit) == 1 {
		if instance != "" {
			return instance + "." + key
		}

		return key
	}

	if instance != "" {
		instanceSection := keySplit[0] + "_" + instance
		if !fallbackSections[keySplit[0]] || v.IsSet(instanceSection) {
			keySplit[0] = instanceSection
		}
	}

	return strings.Join(keySplit, ".")
}
