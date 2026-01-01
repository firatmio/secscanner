// Package scanner provides core types and interfaces for security scanning.
package scanner

import (
	"context"
	"time"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingType represents the category of security finding.
type FindingType string

const (
	FindingTypeSecret           FindingType = "SECRET"
	FindingTypeMisconfiguration FindingType = "MISCONFIGURATION"
	FindingTypeVulnerability    FindingType = "VULNERABILITY"
)

// Finding represents a security issue discovered during scanning.
type Finding struct {
	ID          string            `json:"id" yaml:"id"`
	RuleID      string            `json:"rule_id" yaml:"rule_id"`
	Title       string            `json:"title" yaml:"title"`
	Description string            `json:"description" yaml:"description"`
	Severity    Severity          `json:"severity" yaml:"severity"`
	Type        FindingType       `json:"type" yaml:"type"`
	FilePath    string            `json:"file_path" yaml:"file_path"`
	StartLine   int               `json:"start_line" yaml:"start_line"`
	EndLine     int               `json:"end_line" yaml:"end_line"`
	Match       string            `json:"match,omitempty" yaml:"match,omitempty"`
	Remediation string            `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Timestamp   time.Time         `json:"timestamp" yaml:"timestamp"`
}

// Target represents a scan target (file, URL, or IP).
type Target struct {
	Path     string            `json:"path" yaml:"path"`
	Type     TargetType        `json:"type" yaml:"type"`
	Content  []byte            `json:"-" yaml:"-"`
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// TargetType represents the type of scan target.
type TargetType string

const (
	TargetTypeFile TargetType = "FILE"
	TargetTypeURL  TargetType = "URL"
	TargetTypeIP   TargetType = "IP"
)

// ScanResult contains the results of a scan operation.
type ScanResult struct {
	Target      Target        `json:"target" yaml:"target"`
	Findings    []Finding     `json:"findings" yaml:"findings"`
	ScanTime    time.Duration `json:"scan_time" yaml:"scan_time"`
	Error       error         `json:"-" yaml:"-"`
	ErrorString string        `json:"error,omitempty" yaml:"error,omitempty"`
}

// ScanConfig holds configuration for scan operations.
type ScanConfig struct {
	MaxWorkers      int           `json:"max_workers" yaml:"max_workers"`
	Timeout         time.Duration `json:"timeout" yaml:"timeout"`
	ExcludePatterns []string      `json:"exclude_patterns" yaml:"exclude_patterns"`
	IncludePatterns []string      `json:"include_patterns" yaml:"include_patterns"`
	Severities      []Severity    `json:"severities" yaml:"severities"`
	EnabledRules    []string      `json:"enabled_rules" yaml:"enabled_rules"`
	DisabledRules   []string      `json:"disabled_rules" yaml:"disabled_rules"`
}

// DefaultScanConfig returns a sensible default configuration.
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		MaxWorkers: 10,
		Timeout:    5 * time.Minute,
		ExcludePatterns: []string{
			"**/node_modules/**",
			"**/.git/**",
			"**/vendor/**",
			"**/*.min.js",
			"**/*.min.css",
		},
		Severities: []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow},
	}
}

// Scanner is the interface that all security scanners must implement.
type Scanner interface {
	// Name returns the scanner's unique identifier.
	Name() string

	// Description returns a human-readable description of the scanner.
	Description() string

	// Scan performs security analysis on the given target.
	Scan(ctx context.Context, target Target) ([]Finding, error)

	// SupportedTypes returns the target types this scanner can process.
	SupportedTypes() []TargetType
}

// Rule represents a configurable security rule.
type Rule struct {
	ID          string      `json:"id" yaml:"id"`
	Name        string      `json:"name" yaml:"name"`
	Description string      `json:"description" yaml:"description"`
	Severity    Severity    `json:"severity" yaml:"severity"`
	Type        FindingType `json:"type" yaml:"type"`
	Pattern     string      `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Remediation string      `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Enabled     bool        `json:"enabled" yaml:"enabled"`
	Tags        []string    `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// ScanSummary provides aggregate statistics for a scan.
type ScanSummary struct {
	TotalTargets   int           `json:"total_targets" yaml:"total_targets"`
	ScannedTargets int           `json:"scanned_targets" yaml:"scanned_targets"`
	TotalFindings  int           `json:"total_findings" yaml:"total_findings"`
	CriticalCount  int           `json:"critical_count" yaml:"critical_count"`
	HighCount      int           `json:"high_count" yaml:"high_count"`
	MediumCount    int           `json:"medium_count" yaml:"medium_count"`
	LowCount       int           `json:"low_count" yaml:"low_count"`
	InfoCount      int           `json:"info_count" yaml:"info_count"`
	Errors         int           `json:"errors" yaml:"errors"`
	Duration       time.Duration `json:"duration" yaml:"duration"`
	StartTime      time.Time     `json:"start_time" yaml:"start_time"`
	EndTime        time.Time     `json:"end_time" yaml:"end_time"`
}

// CalculateSummary generates summary statistics from scan results.
func CalculateSummary(results []ScanResult, startTime time.Time) ScanSummary {
	summary := ScanSummary{
		TotalTargets: len(results),
		StartTime:    startTime,
		EndTime:      time.Now(),
	}
	summary.Duration = summary.EndTime.Sub(summary.StartTime)

	for _, result := range results {
		if result.Error != nil {
			summary.Errors++
			continue
		}
		summary.ScannedTargets++
		summary.TotalFindings += len(result.Findings)

		for _, finding := range result.Findings {
			switch finding.Severity {
			case SeverityCritical:
				summary.CriticalCount++
			case SeverityHigh:
				summary.HighCount++
			case SeverityMedium:
				summary.MediumCount++
			case SeverityLow:
				summary.LowCount++
			case SeverityInfo:
				summary.InfoCount++
			}
		}
	}

	return summary
}
