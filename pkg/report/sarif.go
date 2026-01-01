// Package report provides SARIF output format for scan results.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/security-cli/secscanner/pkg/scanner"
)

// SARIFReporter outputs results in SARIF format.
type SARIFReporter struct {
	toolName    string
	toolVersion string
	toolURI     string
}

// NewSARIFReporter creates a new SARIF reporter.
func NewSARIFReporter() *SARIFReporter {
	return &SARIFReporter{
		toolName:    "secscanner",
		toolVersion: "1.0.0",
		toolURI:     "https://github.com/security-cli/secscanner",
	}
}

// Format returns the reporter's format type.
func (r *SARIFReporter) Format() Format {
	return FormatSARIF
}

// Report outputs the scan results in SARIF format.
func (r *SARIFReporter) Report(w io.Writer, results []scanner.ScanResult, summary scanner.ScanSummary) error {
	// Create SARIF report
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return fmt.Errorf("failed to create SARIF report: %w", err)
	}

	// Create run
	run := sarif.NewRunWithInformationURI(r.toolName, r.toolURI)
	run.Tool.Driver.WithVersion(r.toolVersion)
	run.Tool.Driver.WithFullName("SecScanner - Security Scanner CLI")

	// Add organization info
	run.Tool.Driver.WithOrganization("SecScanner Project")

	// Collect unique rules
	ruleMap := make(map[string]*sarif.ReportingDescriptor)

	for _, result := range results {
		for _, finding := range result.Findings {
			if _, exists := ruleMap[finding.RuleID]; !exists {
				rule := run.AddRule(finding.RuleID).
					WithName(finding.Title).
					WithDescription(finding.Description).
					WithHelpURI(r.getHelpURI(finding.RuleID))

				// Set default configuration
				rule.WithDefaultConfiguration(&sarif.ReportingConfiguration{
					Level: r.mapSeverityToLevel(finding.Severity),
				})

				// Add properties
				rule.WithProperties(sarif.Properties{
					"severity":    string(finding.Severity),
					"type":        string(finding.Type),
					"remediation": finding.Remediation,
				})

				ruleMap[finding.RuleID] = rule
			}
		}
	}

	// Add results
	for _, scanResult := range results {
		for _, finding := range scanResult.Findings {
			result := run.CreateResultForRule(finding.RuleID).
				WithMessage(sarif.NewTextMessage(finding.Description)).
				WithLevel(r.mapSeverityToLevel(finding.Severity))

			// Add location
			artifactLocation := sarif.NewSimpleArtifactLocation(r.normalizeFilePath(finding.FilePath))

			physicalLocation := sarif.NewPhysicalLocation().
				WithArtifactLocation(artifactLocation).
				WithRegion(
					sarif.NewRegion().
						WithStartLine(finding.StartLine).
						WithEndLine(finding.EndLine),
				)

			location := sarif.NewLocation().WithPhysicalLocation(physicalLocation)
			result.WithLocations([]*sarif.Location{location})

			// Add fingerprints for deduplication
			result.WithFingerPrints(map[string]interface{}{
				"primaryLocationLineHash": finding.ID,
			})

			// Add related locations for context
			if finding.Match != "" {
				snippet := sarif.NewArtifactContent().WithText(finding.Match)
				physicalLocation.Region.WithSnippet(snippet)
			}
		}
	}

	// Add invocation info
	invocation := sarif.NewInvocation().
		WithExecutionSuccess(true).
		WithStartTimeUTC(summary.StartTime).
		WithEndTimeUTC(summary.EndTime)

	run.Invocations = append(run.Invocations, invocation)

	report.AddRun(run)

	// Write output
	return report.PrettyWrite(w)
}

// mapSeverityToLevel maps scanner severity to SARIF level.
func (r *SARIFReporter) mapSeverityToLevel(severity scanner.Severity) string {
	switch severity {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	case scanner.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// normalizeFilePath converts Windows paths to SARIF-compatible format.
func (r *SARIFReporter) normalizeFilePath(path string) string {
	normalized := strings.ReplaceAll(path, "\\", "/")
	return normalized
}

// getHelpURI returns a help URL for a rule.
func (r *SARIFReporter) getHelpURI(ruleID string) string {
	return fmt.Sprintf("%s/rules/%s", r.toolURI, strings.ToLower(ruleID))
}

// SARIFConverter provides utilities for SARIF format handling.
type SARIFConverter struct{}

// ConvertToSARIF converts scan results to SARIF format string.
func (c *SARIFConverter) ConvertToSARIF(results []scanner.ScanResult, summary scanner.ScanSummary) (string, error) {
	var buf strings.Builder
	reporter := NewSARIFReporter()
	err := reporter.Report(&buf, results, summary)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ValidateSARIF validates a SARIF document.
func ValidateSARIF(data []byte) error {
	// Basic validation - try to parse as SARIF
	_, err := sarif.FromBytes(data)
	return err
}

// MergeSARIFReports merges multiple SARIF reports into one.
func MergeSARIFReports(reports ...*sarif.Report) (*sarif.Report, error) {
	if len(reports) == 0 {
		return sarif.New(sarif.Version210)
	}

	merged, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, err
	}

	for _, report := range reports {
		for _, run := range report.Runs {
			merged.AddRun(run)
		}
	}

	return merged, nil
}

// GenerateGitHubSARIF generates SARIF optimized for GitHub Code Scanning.
func GenerateGitHubSARIF(results []scanner.ScanResult, summary scanner.ScanSummary, repoRoot string) (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, err
	}

	run := sarif.NewRunWithInformationURI("secscanner", "https://github.com/security-cli/secscanner")
	run.Tool.Driver.WithVersion("1.0.0")
	run.Tool.Driver.WithSemanticVersion("1.0.0")

	for _, scanResult := range results {
		for _, finding := range scanResult.Findings {
			// Add rule if not exists
			rule := run.AddRule(finding.RuleID).
				WithName(finding.Title).
				WithDescription(finding.Description)

			rule.WithDefaultConfiguration(&sarif.ReportingConfiguration{
				Level: mapGitHubLevel(finding.Severity),
			})

			// Make path relative to repo root
			relPath := finding.FilePath
			if repoRoot != "" && strings.HasPrefix(finding.FilePath, repoRoot) {
				relPath = strings.TrimPrefix(finding.FilePath, repoRoot)
				relPath = strings.TrimPrefix(relPath, "/")
				relPath = strings.TrimPrefix(relPath, "\\")
			}

			result := run.CreateResultForRule(finding.RuleID).
				WithMessage(sarif.NewTextMessage(finding.Description)).
				WithLevel(mapGitHubLevel(finding.Severity))

			location := sarif.NewLocation().WithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewSimpleArtifactLocation(relPath)).
					WithRegion(sarif.NewRegion().
						WithStartLine(finding.StartLine).
						WithEndLine(finding.EndLine)),
			)
			result.WithLocations([]*sarif.Location{location})
		}
	}

	report.AddRun(run)
	return report, nil
}

// mapGitHubLevel maps severity to GitHub-compatible SARIF level.
func mapGitHubLevel(severity scanner.Severity) string {
	switch severity {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
