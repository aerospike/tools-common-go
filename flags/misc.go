package flags

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// SetupRoot sets up the root command with common flags and options.
// It takes the rootCmd and appLongName as parameters.
// It registers the "help" alias for the "usage" flag.
// It adds the "version" as uppercase "V" flag to the rootCmd.
// It sets the version template for the rootCmd using appLongName. If
// appLongName is "Unique Data Agent", the version template will be:
//
// Unique Data Agent
// Version 1.2.3
func SetupRoot(rootCmd *cobra.Command, appLongName string, version string) {
	sVersion := strings.Split(version, "-")
	build := ""

	version = sVersion[0]
	versionTemplate := fmt.Sprintf("%s\nVersion %s\n", appLongName, version)

	if len(sVersion) >= 2 {
		build = sVersion[len(sVersion)-1]
	}

	if build != "" {
		versionTemplate = fmt.Sprintf("%s\nVersion %s\nBuild %s\n", appLongName, version, build)
	}

	rootCmd.PersistentFlags().BoolP("help", "u", false, "Display help information")
	rootCmd.SetVersionTemplate(versionTemplate)
	rootCmd.PersistentFlags().BoolP("version", "V", false, "Display version.") // All tools use -V
}
