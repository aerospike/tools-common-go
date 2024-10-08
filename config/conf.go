package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// A map that maps config keys i.e. "cluster.host" to flag names i.e. "host".
// This is only needed because if "instance". Otherwise we would just run
// RegisterAlias inside the BindPFlags function.
var configToFlagMap = map[string]string{}
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

			if err := viper.ReadInConfig(); err != nil {
				return "", nil
			}
		} else {
			return "", fmt.Errorf("failed to read config file: %w", err)
		}
	}

	return viper.ConfigFileUsed(), SetFlags(instance, flags)
}

func SetFlags(instance string, flags *pflag.FlagSet) error {
	var persistedErr error

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

		val := viper.GetString(f.Name)

		// Apply the viper config value to the flag when viper has a value
		if viper.IsSet(f.Name) && !f.Changed {
			if err := f.Value.Set(val); err != nil {
				persistedErr = fmt.Errorf("failed to parse flag %s: %s", f.Name, err)
			}
		}
	})

	return persistedErr
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

// Reset resets the global configToFlagMap and viper instance.
// Should be called before or after tests that use InitConfig or BindPFlags.
// If using testify suites call it in the SetupTest function and or
// SetupSubTests if using suite.T().Run(...).
func Reset() {
	configToFlagMap = map[string]string{}

	viper.Reset()
}

func getAlias(key, instance string) string {
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
		keySplit[0] += "_" + instance
	}

	return strings.Join(keySplit, ".")
}
