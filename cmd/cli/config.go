// Package cli provides configuration and rules utilities.
package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/security-cli/secscanner/pkg/scanner"
	"gopkg.in/yaml.v3"
)

// Config represents the secscanner configuration file structure.
type Config struct {
	Version string       `yaml:"version"`
	Scan    ScanConfig   `yaml:"scan"`
	Rules   RulesConfig  `yaml:"rules"`
	Output  OutputConfig `yaml:"output"`
	CI      CIConfig     `yaml:"ci"`
}

// ScanConfig holds scan-related configuration.
type ScanConfig struct {
	Workers         int      `yaml:"workers"`
	Timeout         string   `yaml:"timeout"`
	ExcludePatterns []string `yaml:"exclude"`
	IncludePatterns []string `yaml:"include"`
	FollowSymlinks  bool     `yaml:"follow_symlinks"`
	MaxFileSize     string   `yaml:"max_file_size"`
}

// RulesConfig holds rule-related configuration.
type RulesConfig struct {
	Enabled  []string     `yaml:"enabled"`
	Disabled []string     `yaml:"disabled"`
	Custom   []CustomRule `yaml:"custom"`
}

// CustomRule represents a user-defined rule.
type CustomRule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	Pattern     string   `yaml:"pattern"`
	FileTypes   []string `yaml:"file_types"`
	Remediation string   `yaml:"remediation"`
}

// OutputConfig holds output-related configuration.
type OutputConfig struct {
	Format  string `yaml:"format"`
	File    string `yaml:"file"`
	Color   bool   `yaml:"color"`
	Verbose bool   `yaml:"verbose"`
}

// CIConfig holds CI/CD-related configuration.
type CIConfig struct {
	FailOn           string `yaml:"fail_on"`
	SuppressOutput   bool   `yaml:"suppress_output"`
	AnnotateFindings bool   `yaml:"annotate_findings"`
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1.0",
		Scan: ScanConfig{
			Workers: 10,
			Timeout: "5m",
			ExcludePatterns: []string{
				"**/node_modules/**",
				"**/.git/**",
				"**/vendor/**",
				"**/dist/**",
				"**/build/**",
				"**/*.min.js",
				"**/*.min.css",
				"**/package-lock.json",
				"**/yarn.lock",
			},
			MaxFileSize: "10MB",
		},
		Rules: RulesConfig{
			Enabled:  []string{},
			Disabled: []string{},
			Custom:   []CustomRule{},
		},
		Output: OutputConfig{
			Format:  "table",
			Color:   true,
			Verbose: false,
		},
		CI: CIConfig{
			FailOn:           "high",
			SuppressOutput:   false,
			AnnotateFindings: true,
		},
	}
}

// initConfig creates a default configuration file.
func initConfig() {
	configPath := ".secscanner.yaml"

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil {
		color.Yellow("⚠️  Configuration file already exists: %s\n", configPath)
		fmt.Print("Overwrite? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Aborted.")
			return
		}
	}

	// Generate default config
	config := DefaultConfig()

	// Add example custom rule
	config.Rules.Custom = []CustomRule{
		{
			ID:          "CUSTOM001",
			Name:        "Example Custom Rule",
			Description: "This is an example custom rule - replace with your own",
			Severity:    "MEDIUM",
			Pattern:     "TODO:|FIXME:|HACK:",
			FileTypes:   []string{"*.go", "*.py", "*.js"},
			Remediation: "Address TODO/FIXME comments before production",
		},
	}

	// Marshal to YAML with comments
	data, err := yaml.Marshal(config)
	if err != nil {
		color.Red("❌ Failed to generate configuration: %v\n", err)
		return
	}

	// Add header comment
	header := `# SecScanner Configuration File
# https://github.com/security-cli/secscanner
#
# This file configures the security scanning behavior.
# Place this file in your project root or specify via --config flag.

`

	// Write file
	if err := os.WriteFile(configPath, []byte(header+string(data)), 0644); err != nil {
		color.Red("❌ Failed to write configuration file: %v\n", err)
		return
	}

	color.Green("✅ Configuration file created: %s\n", configPath)
	fmt.Println("\nCustomize the configuration file to match your project needs.")
}

// listRules displays all available security rules.
func listRules() {
	cyan := color.New(color.FgCyan, color.Bold)
	white := color.New(color.FgWhite, color.Bold)

	fmt.Println()
	white.Println("📋 AVAILABLE SECURITY RULES")
	fmt.Println(string(make([]byte, 80)))
	fmt.Println()

	// Secret Scanner Rules
	cyan.Println("🔐 SECRET DETECTION RULES")
	fmt.Println()

	secretScanner := scanner.NewSecretScanner()
	printRuleTable(convertSecretRules(secretScanner.GetRules()))

	fmt.Println()

	// Misconfiguration Rules
	cyan.Println("⚙️  MISCONFIGURATION RULES")
	fmt.Println()

	// Docker rules
	white.Println("  Dockerfile Rules:")
	fmt.Println()

	dockerRules := []ruleInfo{
		{"DOCKER001", "HIGH", "Running as Root User"},
		{"DOCKER002", "MEDIUM", "Using Latest Tag"},
		{"DOCKER003", "MEDIUM", "No Tag Specified"},
		{"DOCKER004", "LOW", "ADD Instead of COPY"},
		{"DOCKER005", "HIGH", "Secrets in Environment Variables"},
		{"DOCKER006", "CRITICAL", "Curl/Wget Piped to Shell"},
		{"DOCKER007", "LOW", "apt-get without --no-install-recommends"},
		{"DOCKER008", "LOW", "Missing apt-get Clean"},
		{"DOCKER009", "MEDIUM", "HEALTHCHECK Not Defined"},
		{"DOCKER010", "MEDIUM", "Privileged Port Exposed"},
		{"DOCKER011", "MEDIUM", "sudo Usage Detected"},
		{"DOCKER012", "HIGH", "Missing USER Instruction"},
	}
	printRuleTable(dockerRules)

	fmt.Println()
	white.Println("  Kubernetes Rules:")
	fmt.Println()

	k8sRules := []ruleInfo{
		{"K8S001", "CRITICAL", "Privileged Container"},
		{"K8S002", "HIGH", "Running as Root"},
		{"K8S003", "MEDIUM", "Root Filesystem Not Read-Only"},
		{"K8S004", "HIGH", "Privilege Escalation Allowed"},
		{"K8S005", "HIGH", "Host Network Access"},
		{"K8S006", "HIGH", "Host PID Namespace"},
		{"K8S007", "MEDIUM", "Host IPC Namespace"},
		{"K8S008", "CRITICAL", "Dangerous Capabilities Added"},
		{"K8S009", "MEDIUM", "No Resource Limits"},
		{"K8S010", "MEDIUM", "Latest Image Tag"},
		{"K8S011", "HIGH", "Host Path Volume Mount"},
		{"K8S012", "LOW", "Default Service Account"},
		{"K8S013", "MEDIUM", "Secrets in Environment Variables"},
		{"K8S014", "MEDIUM", "Missing Network Policy"},
		{"K8S015", "CRITICAL", "Writable /proc Mount"},
		{"K8S016", "MEDIUM", "Missing Security Context"},
		{"K8S017", "MEDIUM", "RunAsNonRoot Not Set"},
	}
	printRuleTable(k8sRules)

	fmt.Println()
	fmt.Println("Use --rules <ID>,<ID> to enable specific rules only")
	fmt.Println("Use --disable-rules <ID>,<ID> to disable specific rules")
	fmt.Println()
}

type ruleInfo struct {
	ID       string
	Severity string
	Name     string
}

func printRuleTable(rules []ruleInfo) {
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	blue := color.New(color.FgBlue)
	magenta := color.New(color.FgMagenta)

	for _, rule := range rules {
		var severityColor *color.Color
		switch rule.Severity {
		case "CRITICAL":
			severityColor = magenta
		case "HIGH":
			severityColor = red
		case "MEDIUM":
			severityColor = yellow
		default:
			severityColor = blue
		}

		fmt.Printf("  %-12s ", rule.ID)
		severityColor.Printf("%-10s", rule.Severity)
		fmt.Printf(" %s\n", rule.Name)
	}
}

func convertSecretRules(rules []scanner.SecretRule) []ruleInfo {
	result := make([]ruleInfo, len(rules))
	for i, r := range rules {
		result[i] = ruleInfo{
			ID:       r.ID,
			Severity: string(r.Severity),
			Name:     r.Name,
		}
	}
	return result
}
