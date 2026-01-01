// Package report provides output formatters for scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/security-cli/secscanner/pkg/scanner"
)

// Format represents the output format type.
type Format string

const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatMarkdown Format = "markdown"
)

// Reporter is the interface for result reporters.
type Reporter interface {
	Report(w io.Writer, results []scanner.ScanResult, summary scanner.ScanSummary) error
	Format() Format
}

// TableReporter outputs results in a formatted table (TUI).
type TableReporter struct {
	colorEnabled bool
	verbose      bool
}

// NewTableReporter creates a new table reporter.
func NewTableReporter(colorEnabled, verbose bool) *TableReporter {
	return &TableReporter{
		colorEnabled: colorEnabled,
		verbose:      verbose,
	}
}

// Format returns the reporter's format type.
func (r *TableReporter) Format() Format {
	return FormatTable
}

// Report outputs the scan results as a formatted table.
func (r *TableReporter) Report(w io.Writer, results []scanner.ScanResult, summary scanner.ScanSummary) error {
	// Color definitions
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	blue := color.New(color.FgBlue)
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)
	magenta := color.New(color.FgMagenta)

	if !r.colorEnabled {
		color.NoColor = true
	}

	// Header
	fmt.Fprintln(w)
	white.Fprintln(w, "╔══════════════════════════════════════════════════════════════════════════════╗")
	white.Fprintln(w, "║                         🔒 SECSCANNER REPORT                                 ║")
	white.Fprintln(w, "╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w)

	// Summary section
	cyan.Fprintln(w, "📊 SCAN SUMMARY")
	fmt.Fprintln(w, strings.Repeat("─", 80))
	fmt.Fprintf(w, "  %-25s %s\n", "Scan Duration:", summary.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "  %-25s %d\n", "Targets Scanned:", summary.ScannedTargets)
	fmt.Fprintf(w, "  %-25s %d\n", "Total Findings:", summary.TotalFindings)
	fmt.Fprintf(w, "  %-25s %d\n", "Errors:", summary.Errors)
	fmt.Fprintln(w)

	// Severity breakdown
	cyan.Fprintln(w, "📈 SEVERITY BREAKDOWN")
	fmt.Fprintln(w, strings.Repeat("─", 80))

	r.printSeverityBar(w, "CRITICAL", summary.CriticalCount, summary.TotalFindings, red)
	r.printSeverityBar(w, "HIGH", summary.HighCount, summary.TotalFindings, red)
	r.printSeverityBar(w, "MEDIUM", summary.MediumCount, summary.TotalFindings, yellow)
	r.printSeverityBar(w, "LOW", summary.LowCount, summary.TotalFindings, blue)
	r.printSeverityBar(w, "INFO", summary.InfoCount, summary.TotalFindings, cyan)
	fmt.Fprintln(w)

	if summary.TotalFindings == 0 {
		green.Fprintln(w, "✅ No security issues found! Your code looks clean.")
		fmt.Fprintln(w)
		return nil
	}

	// Collect and sort findings
	var allFindings []scanner.Finding
	for _, result := range results {
		allFindings = append(allFindings, result.Findings...)
	}

	// Sort by severity (CRITICAL first)
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder(allFindings[i].Severity) < severityOrder(allFindings[j].Severity)
	})

	// Findings detail
	cyan.Fprintln(w, "🔍 DETAILED FINDINGS")
	fmt.Fprintln(w, strings.Repeat("─", 80))
	fmt.Fprintln(w)

	for i, finding := range allFindings {
		// Finding header
		severityColor := r.getSeverityColor(finding.Severity)

		fmt.Fprintf(w, "[%d] ", i+1)
		severityColor.Fprintf(w, "%-10s", finding.Severity)
		white.Fprintf(w, " %s\n", finding.Title)

		magenta.Fprintf(w, "    Rule: %s\n", finding.RuleID)
		fmt.Fprintf(w, "    File: %s:%d\n", finding.FilePath, finding.StartLine)

		if finding.Match != "" && r.verbose {
			fmt.Fprintf(w, "    Match: %s\n", truncate(finding.Match, 60))
		}

		if finding.Description != "" {
			fmt.Fprintf(w, "    Description: %s\n", truncate(finding.Description, 70))
		}

		if finding.Remediation != "" {
			green.Fprintf(w, "    💡 Fix: %s\n", truncate(finding.Remediation, 65))
		}

		fmt.Fprintln(w)
	}

	// Footer
	fmt.Fprintln(w, strings.Repeat("─", 80))
	if summary.CriticalCount > 0 || summary.HighCount > 0 {
		red.Fprintln(w, "⚠️  Critical/High severity issues found. Please review and fix before deployment.")
	} else if summary.MediumCount > 0 {
		yellow.Fprintln(w, "⚡ Medium severity issues found. Consider addressing these issues.")
	} else {
		green.Fprintln(w, "✓ Only low severity issues found. Good job!")
	}
	fmt.Fprintln(w)

	return nil
}

// printSeverityBar prints a visual bar for severity counts.
func (r *TableReporter) printSeverityBar(w io.Writer, label string, count, total int, c *color.Color) {
	barWidth := 40
	filled := 0
	if total > 0 {
		filled = (count * barWidth) / total
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	c.Fprintf(w, "  %-10s [%s] %d\n", label, bar, count)
}

// getSeverityColor returns the appropriate color for a severity level.
func (r *TableReporter) getSeverityColor(severity scanner.Severity) *color.Color {
	switch severity {
	case scanner.SeverityCritical:
		return color.New(color.FgRed, color.Bold, color.BgWhite)
	case scanner.SeverityHigh:
		return color.New(color.FgRed, color.Bold)
	case scanner.SeverityMedium:
		return color.New(color.FgYellow, color.Bold)
	case scanner.SeverityLow:
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgCyan)
	}
}

// severityOrder returns the sort order for severities.
func severityOrder(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 0
	case scanner.SeverityHigh:
		return 1
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityLow:
		return 3
	case scanner.SeverityInfo:
		return 4
	default:
		return 5
	}
}

// truncate shortens a string to max length with ellipsis.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// JSONReporter outputs results in JSON format.
type JSONReporter struct {
	pretty bool
}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter(pretty bool) *JSONReporter {
	return &JSONReporter{pretty: pretty}
}

// Format returns the reporter's format type.
func (r *JSONReporter) Format() Format {
	return FormatJSON
}

// JSONReport represents the JSON output structure.
type JSONReport struct {
	Version   string               `json:"version"`
	Timestamp time.Time            `json:"timestamp"`
	Summary   scanner.ScanSummary  `json:"summary"`
	Results   []scanner.ScanResult `json:"results"`
}

// Report outputs the scan results as JSON.
func (r *JSONReporter) Report(w io.Writer, results []scanner.ScanResult, summary scanner.ScanSummary) error {
	report := JSONReport{
		Version:   "1.0.0",
		Timestamp: time.Now(),
		Summary:   summary,
		Results:   results,
	}

	encoder := json.NewEncoder(w)
	if r.pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}

// MarkdownReporter outputs results in Markdown format.
type MarkdownReporter struct{}

// NewMarkdownReporter creates a new Markdown reporter.
func NewMarkdownReporter() *MarkdownReporter {
	return &MarkdownReporter{}
}

// Format returns the reporter's format type.
func (r *MarkdownReporter) Format() Format {
	return FormatMarkdown
}

// Report outputs the scan results as Markdown.
func (r *MarkdownReporter) Report(w io.Writer, results []scanner.ScanResult, summary scanner.ScanSummary) error {
	fmt.Fprintln(w, "# 🔒 Security Scan Report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Scan Date:** %s\n\n", summary.StartTime.Format(time.RFC3339))

	fmt.Fprintln(w, "## 📊 Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Metric | Value |")
	fmt.Fprintln(w, "|--------|-------|")
	fmt.Fprintf(w, "| Duration | %s |\n", summary.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "| Targets Scanned | %d |\n", summary.ScannedTargets)
	fmt.Fprintf(w, "| Total Findings | %d |\n", summary.TotalFindings)
	fmt.Fprintf(w, "| Critical | %d |\n", summary.CriticalCount)
	fmt.Fprintf(w, "| High | %d |\n", summary.HighCount)
	fmt.Fprintf(w, "| Medium | %d |\n", summary.MediumCount)
	fmt.Fprintf(w, "| Low | %d |\n", summary.LowCount)
	fmt.Fprintln(w)

	if summary.TotalFindings == 0 {
		fmt.Fprintln(w, "✅ **No security issues found!**")
		return nil
	}

	fmt.Fprintln(w, "## 🔍 Findings")
	fmt.Fprintln(w)

	findingNum := 0
	for _, result := range results {
		for _, finding := range result.Findings {
			findingNum++
			emoji := r.getSeverityEmoji(finding.Severity)

			fmt.Fprintf(w, "### %s %d. %s\n\n", emoji, findingNum, finding.Title)
			fmt.Fprintf(w, "- **Severity:** %s\n", finding.Severity)
			fmt.Fprintf(w, "- **Rule:** `%s`\n", finding.RuleID)
			fmt.Fprintf(w, "- **File:** `%s:%d`\n", finding.FilePath, finding.StartLine)
			fmt.Fprintln(w)

			if finding.Description != "" {
				fmt.Fprintf(w, "**Description:** %s\n\n", finding.Description)
			}

			if finding.Match != "" {
				fmt.Fprintln(w, "**Match:**")
				fmt.Fprintf(w, "```\n%s\n```\n\n", finding.Match)
			}

			if finding.Remediation != "" {
				fmt.Fprintf(w, "> 💡 **Remediation:** %s\n\n", finding.Remediation)
			}

			fmt.Fprintln(w, "---")
			fmt.Fprintln(w)
		}
	}

	return nil
}

// getSeverityEmoji returns an emoji for the severity level.
func (r *MarkdownReporter) getSeverityEmoji(severity scanner.Severity) string {
	switch severity {
	case scanner.SeverityCritical:
		return "🔴"
	case scanner.SeverityHigh:
		return "🟠"
	case scanner.SeverityMedium:
		return "🟡"
	case scanner.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

// GetReporter returns the appropriate reporter for the given format.
func GetReporter(format Format, options ...interface{}) Reporter {
	switch format {
	case FormatJSON:
		pretty := true
		if len(options) > 0 {
			if p, ok := options[0].(bool); ok {
				pretty = p
			}
		}
		return NewJSONReporter(pretty)
	case FormatMarkdown:
		return NewMarkdownReporter()
	case FormatSARIF:
		return NewSARIFReporter()
	default:
		colorEnabled := true
		verbose := true
		if len(options) > 0 {
			if c, ok := options[0].(bool); ok {
				colorEnabled = c
			}
		}
		if len(options) > 1 {
			if v, ok := options[1].(bool); ok {
				verbose = v
			}
		}
		return NewTableReporter(colorEnabled, verbose)
	}
}
