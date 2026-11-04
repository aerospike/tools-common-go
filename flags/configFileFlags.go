package flags

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/aerospike/tools-common-go/config"
	"github.com/spf13/pflag"
)

// ConfFileFlags represents the flags related to setting up the config file.
// Pass Files() to config.InitConfigFiles. config.InitConfig reads File only, so
// --only-config-file and --no-config-file do nothing there.
type ConfFileFlags struct {
	File     string // Config file read after the default ones.
	OnlyFile string // The only config file read.
	Instance string // Instance name appended to top-level context e.g. instance=tls will read from cluster_tls.
	NoFile   bool   // Read no config file.
}

func NewConfFileFlags() *ConfFileFlags {
	return &ConfFileFlags{}
}

// NewFlagSet creates a new pflag.FlagSet with the config file flags.
// The fmtUsage parameter is a function that formats the usage string. The
// help names the default files, so call config.SetDefaultConfName and
// config.SetSystemConfDir first.
func (cf *ConfFileFlags) NewFlagSet(fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}

	name := config.ConfName()

	f.Var(pathValue{&cf.File}, "config-file", fmtUsage(fmt.Sprintf(
		"Read this config file after %s and ~/.aerospike/%s.conf."+
			" A later file overrides an earlier one, key by key.",
		filepath.Join(config.SystemConfDir(), name+".conf"), name)))
	f.Var(pathValue{&cf.OnlyFile}, "only-config-file", fmtUsage("Read only this config file."+
		" Cannot be combined with --config-file or --no-config-file."))
	f.BoolVar(&cf.NoFile, "no-config-file", false, fmtUsage("Do not read any config file."+
		" Cannot be combined with --config-file or --only-config-file."))
	f.StringVar(&cf.Instance, "instance", "", fmtUsage("Sections with this instance are read. With instance 'a',"+
		" the sections cluster_a and secret-agent_a are read."))

	return f
}

// Files returns the config files the flags select, for config.InitConfigFiles.
func (cf *ConfFileFlags) Files() config.Files {
	return config.Files{File: cf.File, Only: cf.OnlyFile, None: cf.NoFile}
}

// pathValue is a config file path. An empty one is rejected, where the C tools
// warn that the file cannot be read.
type pathValue struct{ path *string }

func (v pathValue) String() string {
	if v.path == nil {
		return ""
	}

	return *v.path
}

func (v pathValue) Set(path string) error {
	if path == "" {
		return errors.New("expected a path")
	}

	*v.path = path

	return nil
}

func (pathValue) Type() string {
	return "string"
}
