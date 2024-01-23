package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func getAlias(key string, instance string) string {

	if instance != "" {
		instance = "_" + instance
	}

	keySplit := strings.SplitN(key, ".", 2)

	if len(keySplit) == 1 {
		return key
	}

	keySplit[0] += instance

	return strings.Join(keySplit, ".")
}

// initConfig reads in config file and ENV variables if set.
func InitConfig(cfgFile string, instance string, flags *pflag.FlagSet) (string, error) {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
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
		name := f.Name
		alias := getAlias(name, instance)

		if alias != name {
			viper.RegisterAlias(f.Name, alias)
			name = alias
		}

		val := viper.GetString(f.Name)

		// Apply the viper config value to the flag when viper has a value
		if viper.IsSet(f.Name) || viper.IsSet(name) {
			if err := flags.Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				persistedErr = fmt.Errorf("failed to parse flag %s: %s", f.Name, err)
			}
		}
	})

	return configFileUsed, persistedErr
}
