package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
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
// It does not follow [include]; InitConfigFiles does.
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

	file := viper.ConfigFileUsed()

	if ext := filepath.Ext(file); ext == ".conf" || ext == ".toml" {
		if err := checkFileSectionCase(file, instance); err != nil {
			return "", err
		}
	}

	return file, SetFlags(instance, flags)
}

func checkFileSectionCase(file, instance string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := checkSectionCase(raw, instance); err != nil {
		return fmt.Errorf("config file %s: %w", file, err)
	}

	return nil
}

// Directory of the system-wide file InitConfigFiles reads.
var systemConfDir = DefaultConfDir

// The deepest [include] level the C tools read, the top-level files being 0.
const maxIncludeLevel = 3

// InitConfigFiles is InitConfig with the config file loading of the Aerospike
// C tools. It reads /etc/aerospike/<name>.conf, then
// $HOME/.aerospike/<name>.conf, then userProvidedCfgFile when given, and never
// <name>.conf in the working directory. Every file is read as TOML. A missing
// default file is skipped. A userProvidedCfgFile that is missing or cannot be
// read is an error, where the C tools warn and go on, since it may hold the
// Secret Agent CA file.
//
// The files of a file's [include] section are read right after it: file, then
// every regular file under directory in name order, without following links to
// directories. A missing included file is skipped, and an included file more
// than 3 levels deep is an error. Any other error inside an included
// directory, such as an entry that cannot be parsed or a subdirectory that
// cannot be read, fails the load, where the C tools skip the entry, since it
// may hold the Secret Agent CA file. Warnings, such as for a file that cannot
// be opened, are written to standard error.
//
// Values merge key by key, a later file wins, and the command line wins over
// all files. A section bound with BindPFlagsWithInstanceFallback is selected in
// each file before the merge, and a section whose name matches only when case
// is ignored is an error. It returns the files read, in order.
func InitConfigFiles(userProvidedCfgFile, instance string, flags *pflag.FlagSet) ([]string, error) {
	paths := []string{filepath.Join(systemConfDir, confName+".conf")}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".aerospike", confName+".conf"))
	}

	defaults := len(paths)

	if userProvidedCfgFile != "" {
		paths = append(paths, userProvidedCfgFile)
	}

	loader := configLoader{instance: instance}

	for i, path := range paths {
		if err := loader.load(path, 0, i < defaults); err != nil {
			return nil, err
		}
	}

	return loader.paths, setFlags(instance, flags, loader.files)
}

type configLoader struct {
	instance string
	paths    []string
	files    []*viper.Viper
}

// load reads path and the files it includes. An optional file, a default or
// an included one, is skipped when missing or, with a warning, when it cannot
// be opened.
func (l *configLoader) load(path string, level int, optional bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		var pathErr *fs.PathError
		if optional && errors.As(err, &pathErr) && pathErr.Op == "open" {
			warnCannotRead(path, err)
			return nil
		}

		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if level > maxIncludeLevel {
		return fmt.Errorf("config file %s: [include] is nested more than %d levels deep", path, maxIncludeLevel)
	}

	if err := checkSectionCase(raw, l.instance); err != nil {
		return fmt.Errorf("config file %s: %w", path, err)
	}

	file := viper.New()
	file.SetConfigFile(path)
	file.SetConfigType("toml")

	if err := file.ReadConfig(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := viper.MergeConfigMap(selectSections(file, l.instance)); err != nil {
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	l.paths = append(l.paths, path)
	l.files = append(l.files, file)

	return l.include(path, raw, level+1)
}

// include reads the files of the [include] section of path, whose TOML is raw.
func (l *configLoader) include(path string, raw map[string]any, level int) error {
	section, _ := raw["include"].(map[string]any)

	var files, dirs []string

	for _, key := range slices.Sorted(maps.Keys(section)) {
		value, ok := section[key].(string)

		switch {
		case !strings.EqualFold(key, "file") && !strings.EqualFold(key, "directory"):
			return fmt.Errorf("config file %s: unknown key %s in the [include] config section", path, key)
		case !ok:
			return fmt.Errorf(`config file %s: invalid value "%v" for %s in the [include] config section, expected a path`,
				path, section[key], key)
		case strings.EqualFold(key, "file"):
			files = append(files, value)
		default:
			dirs = append(dirs, value)
		}
	}

	for _, file := range files {
		if err := l.load(file, level, true); err != nil {
			return err
		}
	}

	for _, dir := range dirs {
		if err := l.loadDir(path, dir, level); err != nil {
			return err
		}
	}

	return nil
}

// loadDir reads the regular files under dir, which the file from includes.
func (l *configLoader) loadDir(from, dir string, level int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("config file %s: cannot read config directory %s: %s", from, dir, errnoText(err))
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			if err := l.loadDir(from, path, level); err != nil {
				return err
			}

			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			warnCannotRead(path, err)
			continue
		}

		if info.Mode().IsRegular() {
			if err := l.load(path, level, true); err != nil {
				return err
			}
		}
	}

	return nil
}

func warnCannotRead(path string, err error) {
	fmt.Fprintf(os.Stderr, "Warning: cannot read config file %s: %s\n", path, errnoText(err))
}

// checkSectionCase rejects a section that matches a section bound with
// BindPFlagsWithInstanceFallback only when case is ignored, since viper reads
// it but the C tools, which match section names exactly, do not.
func checkSectionCase(raw map[string]any, instance string) error {
	for _, base := range slices.Sorted(maps.Keys(fallbackSections)) {
		names := []string{base}
		if instance != "" {
			names = append(names, base+"_"+instance)
		}

		for _, name := range names {
			for _, key := range slices.Sorted(maps.Keys(raw)) {
				if key != name && strings.EqualFold(key, name) {
					return fmt.Errorf("the [%s] config section differs from [%s] only in case", key, name)
				}
			}
		}
	}

	return nil
}

// errnoText is the system error text of err, capitalized as the C tools print
// it.
func errnoText(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}

	text := err.Error()

	return strings.ToUpper(text[:1]) + text[1:]
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
			deleteKey(settings, strings.ToLower(section))
		}
	}

	return settings
}

// deleteKey deletes key from settings, nested by its dots as viper nests them.
func deleteKey(settings map[string]any, key string) {
	path := strings.Split(key, ".")

	for _, name := range path[:len(path)-1] {
		next, ok := settings[name].(map[string]any)
		if !ok {
			return
		}

		settings = next
	}

	delete(settings, path[len(path)-1])
}

// splitKey splits a viper key at its last dot into a section and a flag name,
// since an instance name may hold dots but a flag name does not.
func splitKey(key string) (section, name string, nested bool) {
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return "", key, false
	}

	return key[:i], key[i+1:], true
}

// fallbackSection is <base>_<instance> when that is a table in v, and base
// otherwise, as in asbackup and aql.
func fallbackSection(v *viper.Viper, base, instance string) string {
	if section := base + "_" + instance; instance != "" && isTable(v, section) {
		return section
	}

	return base
}

func isTable(v *viper.Viper, key string) bool {
	_, ok := v.Get(key).(map[string]any)

	return ok
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

		section, key, nested := splitKey(alias)
		if base, _, _ := splitKey(configToFlagMap[f.Name]); nested && fallbackSections[base] {
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
		section, key, nested := splitKey(aliasIn(file, f.Name, instance))

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
		if !fallbackSections[keySplit[0]] || isTable(v, instanceSection) {
			keySplit[0] = instanceSection
		}
	}

	return strings.Join(keySplit, ".")
}
