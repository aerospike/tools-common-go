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

// InitConfig reads in config file and ENV variables if set. Should be called
// from the root commands PersistentPreRunE function with the flags of the current command.
func InitConfig(cfgFile string, instance string, flags *pflag.FlagSet) (string, error) {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath(ASTOOLS_CONF_DIR)
		viper.SetConfigName(ASTOOLS_CONF_NAME)
	}

	var configFileUsed string

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		configFileUsed = viper.ConfigFileUsed()
	} else {
		// If .conf then explicitly set type to toml.
		viper.SetConfigType("toml")
		if err := viper.ReadInConfig(); err == nil {
			configFileUsed = viper.ConfigFileUsed()
		} else if cfgFile != "" {
			return "", fmt.Errorf("failed to read config file: %w", err)
		}
	}

	if configFileUsed == "" {
		return "", nil
	}

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
		viper.BindPFlag(alias, f)

		val := viper.GetString(f.Name)

		// Apply the viper config value to the flag when viper has a value
		if viper.IsSet(f.Name) && !f.Changed {
			if err := f.Value.Set(fmt.Sprintf("%v", val)); err != nil {
				persistedErr = fmt.Errorf("failed to parse flag %s: %s", f.Name, err)
			}
		}
	})

	return configFileUsed, persistedErr
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

func getAlias(key string, instance string) string {
	if instance != "" {
		instance = "_" + instance
	}

	if k, ok := configToFlagMap[key]; ok {
		key = k
	}

	keySplit := strings.SplitN(key, ".", 2)

	if len(keySplit) == 1 {
		return key
	}

	keySplit[0] += instance

	return strings.Join(keySplit, ".")
}
