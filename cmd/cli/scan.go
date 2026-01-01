// Package cli provides the scan command implementation.
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/security-cli/secscanner/pkg/report"
	"github.com/security-cli/secscanner/pkg/scanner"
	"github.com/security-cli/secscanner/pkg/utils"
)

var (
	// Scan flags
	format         string
	workers        int
	timeout        time.Duration
	excludes       []string
	includes       []string
	severities     []string
	enabledRules   []string
	disabledRules  []string
	scannerTypes   []string
	failOnSeverity string
	showProgress   bool
)

// scanCmd represents the scan command.
var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan files for security issues",
	Long: `Scan specified paths for security vulnerabilities, secrets, and misconfigurations.

By default, scans the current directory recursively. Multiple paths can be specified.

Output Formats:
  table    - Pretty printed terminal output (default)
  json     - JSON format for programmatic use
  sarif    - SARIF format for GitHub Code Scanning
  markdown - Markdown format for documentation

Scanner Types:
  secrets    - Detect leaked secrets and credentials
  misconfig  - Detect Dockerfile and Kubernetes misconfigurations
  all        - Run all scanners (default)

Examples:
  # Basic scan
  secscanner scan .

  # Scan multiple paths
  secscanner scan ./src ./configs

  # Output to file
  secscanner scan . -o results.json -f json

  # Custom exclusions
  secscanner scan . --exclude "**/test/**" --exclude "**/*.md"

  # Filter by severity
  secscanner scan . --severity critical,high

  # Run specific scanners
  secscanner scan . --scanners secrets

  # Fail CI on high severity findings
  secscanner scan . --fail-on high`,
	Args: cobra.MinimumNArgs(0),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json, sarif, markdown")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 10, "Number of parallel workers")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Minute, "Scan timeout")
	scanCmd.Flags().StringSliceVarP(&excludes, "exclude", "e", nil, "Exclude patterns (glob)")
	scanCmd.Flags().StringSliceVarP(&includes, "include", "i", nil, "Include patterns (glob)")
	scanCmd.Flags().StringSliceVar(&severities, "severity", nil, "Filter by severity: critical,high,medium,low,info")
	scanCmd.Flags().StringSliceVar(&enabledRules, "rules", nil, "Enable specific rules by ID")
	scanCmd.Flags().StringSliceVar(&disabledRules, "disable-rules", nil, "Disable specific rules by ID")
	scanCmd.Flags().StringSliceVar(&scannerTypes, "scanners", []string{"all"}, "Scanners to run: secrets,misconfig,all")
	scanCmd.Flags().StringVar(&failOnSeverity, "fail-on", "", "Exit with error if findings match severity: critical,high,medium,low")
	scanCmd.Flags().BoolVar(&showProgress, "progress", true, "Show progress bar")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Default to current directory
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	// Print banner unless quiet
	if !quiet {
		fmt.Println(getBanner())
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Store start time in context
	startTime := time.Now()
	ctx = context.WithValue(ctx, "start_time", startTime)

	// Initialize scanners
	var scanners []scanner.Scanner

	runSecrets := contains(scannerTypes, "all") || contains(scannerTypes, "secrets")
	runMisconfig := contains(scannerTypes, "all") || contains(scannerTypes, "misconfig")

	if runSecrets {
		scanners = append(scanners, scanner.NewSecretScanner())
	}
	if runMisconfig {
		scanners = append(scanners, scanner.NewMisconfigScanner())
	}

	if len(scanners) == 0 {
		return fmt.Errorf("no scanners enabled")
	}

	// Configure scan
	config := scanner.DefaultScanConfig()
	config.MaxWorkers = workers
	config.Timeout = timeout
	if len(excludes) > 0 {
		config.ExcludePatterns = append(config.ExcludePatterns, excludes...)
	}
	if len(includes) > 0 {
		config.IncludePatterns = includes
	}
	if len(enabledRules) > 0 {
		config.EnabledRules = enabledRules
	}
	if len(disabledRules) > 0 {
		config.DisabledRules = disabledRules
	}

	// Collect targets
	if !quiet {
		cyan := color.New(color.FgCyan)
		cyan.Printf("📁 Collecting files from %d path(s)...\n", len(paths))
	}

	var allTargets []scanner.Target
	walker := utils.NewFileWalker(
		utils.WithExcludePatterns(config.ExcludePatterns),
		utils.WithIncludePatterns(config.IncludePatterns),
	)

	for _, path := range paths {
		targets, err := walker.Walk(path)
		if err != nil {
			color.Red("⚠️  Error walking %s: %v\n", path, err)
			continue
		}
		allTargets = append(allTargets, targets...)
	}

	if len(allTargets) == 0 {
		color.Yellow("⚠️  No files found to scan\n")
		return nil
	}

	if !quiet {
		color.Green("✓ Found %d files to scan\n\n", len(allTargets))
	}

	// Initialize progress
	var progress *utils.Progress
	if showProgress && !quiet {
		progress = utils.NewProgress(len(allTargets), true, os.Stdout)
	}

	// Run scan
	engine := scanner.NewScanEngine(config, scanners...)

	// Collect results with progress updates
	var results []scanner.ScanResult
	resultChan := make(chan scanner.ScanResult, workers)

	go engine.ScanAsync(ctx, allTargets, resultChan)

	for result := range resultChan {
		results = append(results, result)
		if progress != nil {
			progress.Increment()
		}
	}

	if progress != nil {
		progress.Finish()
	}

	// Calculate summary
	summary := scanner.CalculateSummary(results, startTime)

	// Generate report
	var reporter report.Reporter
	switch strings.ToLower(format) {
	case "json":
		reporter = report.NewJSONReporter(true)
	case "sarif":
		reporter = report.NewSARIFReporter()
	case "markdown", "md":
		reporter = report.NewMarkdownReporter()
	default:
		reporter = report.NewTableReporter(!noColor, verbose)
	}

	// Output to file or stdout
	var output *os.File
	if outputFile != "" {
		var err error
		output, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	if err := reporter.Report(output, results, summary); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if outputFile != "" && !quiet {
		color.Green("\n✓ Report saved to %s\n", outputFile)
	}

	// Check fail-on threshold
	if failOnSeverity != "" {
		exitCode := checkFailThreshold(summary, failOnSeverity)
		if exitCode != 0 {
			return fmt.Errorf("findings exceed severity threshold")
		}
	}

	return nil
}

// contains checks if a slice contains a string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// checkFailThreshold checks if findings exceed the severity threshold.
func checkFailThreshold(summary scanner.ScanSummary, threshold string) int {
	switch strings.ToLower(threshold) {
	case "critical":
		if summary.CriticalCount > 0 {
			return 1
		}
	case "high":
		if summary.CriticalCount > 0 || summary.HighCount > 0 {
			return 1
		}
	case "medium":
		if summary.CriticalCount > 0 || summary.HighCount > 0 || summary.MediumCount > 0 {
			return 1
		}
	case "low":
		if summary.TotalFindings > summary.InfoCount {
			return 1
		}
	}
	return 0
}
