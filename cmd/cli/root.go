// Package cli provides the command line interface for secscanner.
package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Version information
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"

	// Global flags
	verbose    bool
	quiet      bool
	noColor    bool
	outputFile string
	configFile string
)

// SetVersionInfo sets the version information from build flags.
func SetVersionInfo(version, commit, buildDate string) {
	Version = version
	Commit = commit
	BuildDate = buildDate
}

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "secscanner",
	Short: "🔒 SecScanner - Cloud-Native Security Scanner",
	Long: getBanner() + `
SecScanner is a high-performance, modular security scanning tool designed for 
modern DevOps workflows. It detects secrets, misconfigurations, and security 
vulnerabilities in your codebase and infrastructure configurations.

Features:
  • Secret Detection   - Find leaked API keys, tokens, and credentials
  • Misconfig Scanner  - Detect Dockerfile and Kubernetes security issues
  • Multiple Outputs   - JSON, SARIF, Markdown, and pretty terminal output
  • CI/CD Ready       - Easy integration with GitHub Actions, GitLab CI, etc.
  • High Performance   - Parallel scanning with configurable worker pools

Examples:
  # Scan current directory
  secscanner scan .

  # Scan with specific output format
  secscanner scan ./src --format json --output results.json

  # Scan only for secrets
  secscanner scan . --scanners secrets

  # Generate SARIF report for GitHub Code Scanning
  secscanner scan . --format sarif --output results.sarif`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if noColor {
			color.NoColor = true
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress all output except errors")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file path")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(initConfigCmd)
}

// getBanner returns the ASCII art banner.
func getBanner() string {
	cyan := color.New(color.FgCyan).SprintFunc()
	return cyan(`
   _____           _____                                 
  / ____|         / ____|                                
 | (___   ___  __| (___   ___ __ _ _ __  _ __   ___ _ __ 
  \___ \ / _ \/ __|\___ \ / __/ _`+"`"+` | '_ \| '_ \ / _ \ '__|
  ____) |  __/ (__ ____) | (_| (_| | | | | | | |  __/ |   
 |_____/ \___|\___|_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                          
`) + "  Cloud-Native Security Scanner v" + Version + "\n"
}

// versionCmd represents the version command.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("SecScanner %s\n", Version)
		fmt.Printf("  Commit:     %s\n", Commit)
		fmt.Printf("  Build Date: %s\n", BuildDate)
		fmt.Printf("  Go Version: %s\n", "go1.23")
		fmt.Printf("  Platform:   %s/%s\n", os.Getenv("GOOS"), os.Getenv("GOARCH"))
	},
}

// rulesCmd represents the rules command.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List available security rules",
	Long:  "Display all available security rules with their IDs, severity, and descriptions.",
	Run: func(cmd *cobra.Command, args []string) {
		listRules()
	},
}

// initConfigCmd represents the init command.
var initConfigCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a configuration file",
	Long:  "Create a default .secscanner.yaml configuration file in the current directory.",
	Run: func(cmd *cobra.Command, args []string) {
		initConfig()
	},
}
