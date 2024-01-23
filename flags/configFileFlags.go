package flags

import (
	"fmt"

	"github.com/aerospike/tools-common-go/config"
	"github.com/spf13/pflag"
)

// TODO: doc string
type ConfFileFlags struct {
	file     string
	instance string
}

func NewConfFileFlags() *ConfFileFlags {
	return &ConfFileFlags{}
}

// TODO: doc string
func NewConfFileFlagSet(cf *ConfFileFlags, fmtUsage UsageFormatter) *pflag.FlagSet {
	f := &pflag.FlagSet{}

	f.StringVar(&cf.file, "config-file", "", DefaultWrapHelpString(fmt.Sprintf("Config file (default is %s/%s)", config.ASTOOLS_CONF_DIR, config.ASTOOLS_CONF_NAME)))
	f.StringVar(&cf.instance, "instance", "", DefaultWrapHelpString("For support of the aerospike tools toml schema. Sections with the instance are read. e.g in the case where instance 'a' is specified sections 'cluster_a', 'uda_a' are read."))

	return f
}
