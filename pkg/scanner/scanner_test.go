package scanner

import (
	"context"
	"testing"
	"time"
)

func TestSecretScanner_ScanAWSKeys(t *testing.T) {
	scanner := NewSecretScanner()

	tests := []struct {
		name     string
		content  string
		expected int
		ruleID   string
	}{
		{
			name:     "AWS Access Key ID",
			content:  `AKIAIOSFODNN7EXAMPLE`,
			expected: 1,
			ruleID:   "SEC001",
		},
		{
			name:     "AWS Secret in variable",
			content:  `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			expected: 1,
			ruleID:   "SEC002",
		},
		{
			name:     "No secrets",
			content:  `const message = "Hello, World!"`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := Target{
				Path:    "test.go",
				Type:    TargetTypeFile,
				Content: []byte(tt.content),
			}

			findings, err := scanner.Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if len(findings) != tt.expected {
				t.Errorf("Expected %d findings, got %d", tt.expected, len(findings))
			}

			if tt.expected > 0 && len(findings) > 0 && tt.ruleID != "" {
				if findings[0].RuleID != tt.ruleID {
					t.Errorf("Expected rule %s, got %s", tt.ruleID, findings[0].RuleID)
				}
			}
		})
	}
}

func TestSecretScanner_ScanGitHubTokens(t *testing.T) {
	scanner := NewSecretScanner()

	content := `
	// GitHub token for CI
	const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	`

	target := Target{
		Path:    "config.js",
		Type:    TargetTypeFile,
		Content: []byte(content),
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}

	if len(findings) > 0 && findings[0].RuleID != "SEC003" {
		t.Errorf("Expected SEC003, got %s", findings[0].RuleID)
	}
}

func TestSecretScanner_MaskSecret(t *testing.T) {
	scanner := NewSecretScanner()

	tests := []struct {
		input    string
		expected string
	}{
		{"short", "*****"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"password123", "pass***123"},
	}

	for _, tt := range tests {
		result := scanner.maskSecret(tt.input)
		if result != tt.expected {
			t.Errorf("maskSecret(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestSecretScanner_AllowlistFiltering(t *testing.T) {
	scanner := NewSecretScanner()

	// Test content with example JWT that should be allowlisted
	content := `const exampleToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkV4YW1wbGUiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`

	target := Target{
		Path:    "example.js",
		Type:    TargetTypeFile,
		Content: []byte(content),
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// JWT with "example" should be filtered
	if len(findings) > 0 {
		for _, f := range findings {
			if f.RuleID == "SEC013" {
				t.Error("Expected JWT with 'example' to be filtered by allowlist")
			}
		}
	}
}

func TestSecretScanner_ContextCancellation(t *testing.T) {
	scanner := NewSecretScanner()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	target := Target{
		Path:    "test.go",
		Type:    TargetTypeFile,
		Content: []byte("AKIAIOSFODNN7EXAMPLE"),
	}

	_, err := scanner.Scan(ctx, target)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestMisconfigScanner_DockerfileRootUser(t *testing.T) {
	scanner := NewMisconfigScanner()

	content := `FROM ubuntu:20.04
RUN apt-get update
USER root
CMD ["./app"]`

	target := Target{
		Path:    "Dockerfile",
		Type:    TargetTypeFile,
		Content: []byte(content),
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	foundRootUser := false
	for _, f := range findings {
		if f.RuleID == "DOCKER001" {
			foundRootUser = true
			break
		}
	}

	if !foundRootUser {
		t.Error("Expected to find DOCKER001 (Running as Root User)")
	}
}

func TestMisconfigScanner_DockerfileLatestTag(t *testing.T) {
	scanner := NewMisconfigScanner()

	content := `FROM nginx:latest
COPY . /app
CMD ["nginx"]`

	target := Target{
		Path:    "Dockerfile",
		Type:    TargetTypeFile,
		Content: []byte(content),
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	foundLatestTag := false
	for _, f := range findings {
		if f.RuleID == "DOCKER002" {
			foundLatestTag = true
			break
		}
	}

	if !foundLatestTag {
		t.Error("Expected to find DOCKER002 (Using Latest Tag)")
	}
}

func TestMisconfigScanner_KubernetesPrivileged(t *testing.T) {
	scanner := NewMisconfigScanner()

	content := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true`

	target := Target{
		Path:    "pod.yaml",
		Type:    TargetTypeFile,
		Content: []byte(content),
	}

	findings, err := scanner.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	foundPrivileged := false
	for _, f := range findings {
		if f.RuleID == "K8S001" {
			foundPrivileged = true
			break
		}
	}

	if !foundPrivileged {
		t.Error("Expected to find K8S001 (Privileged Container)")
	}
}

func TestMisconfigScanner_IsDockerfile(t *testing.T) {
	scanner := NewMisconfigScanner()

	tests := []struct {
		path     string
		expected bool
	}{
		{"Dockerfile", true},
		{"dockerfile", true},
		{"Dockerfile.prod", true},
		{"app.dockerfile", true},
		{"main.go", false},
		{"docker-compose.yaml", false},
	}

	for _, tt := range tests {
		result := scanner.isDockerfile(tt.path)
		if result != tt.expected {
			t.Errorf("isDockerfile(%s) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestMisconfigScanner_IsKubernetesManifest(t *testing.T) {
	scanner := NewMisconfigScanner()

	tests := []struct {
		path     string
		content  string
		expected bool
	}{
		{
			path:     "deployment.yaml",
			content:  "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test",
			expected: true,
		},
		{
			path:     "config.yml",
			content:  "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test",
			expected: true,
		},
		{
			path:     "config.yaml",
			content:  "database:\n  host: localhost",
			expected: false,
		},
		{
			path:     "main.go",
			content:  "package main",
			expected: false,
		},
	}

	for _, tt := range tests {
		result := scanner.isKubernetesManifest(tt.path, []byte(tt.content))
		if result != tt.expected {
			t.Errorf("isKubernetesManifest(%s) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestWorkerPool_BasicOperation(t *testing.T) {
	ctx := context.Background()
	secretScanner := NewSecretScanner()

	pool := NewWorkerPool(ctx, 2, []Scanner{secretScanner})
	pool.Start()

	// Submit a job
	pool.Submit(Job{
		Target: Target{
			Path:    "test.go",
			Type:    TargetTypeFile,
			Content: []byte("const key = 'AKIAIOSFODNN7EXAMPLE'"),
		},
		Config: DefaultScanConfig(),
	})

	// Close and collect results
	go func() {
		time.Sleep(100 * time.Millisecond)
		pool.Close()
	}()

	resultCount := 0
	for range pool.Results() {
		resultCount++
	}

	if resultCount != 1 {
		t.Errorf("Expected 1 result, got %d", resultCount)
	}
}

func TestWorkerPool_Stats(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 4, []Scanner{})
	pool.Start()

	stats := pool.Stats()
	if stats.Workers != 4 {
		t.Errorf("Expected 4 workers, got %d", stats.Workers)
	}

	pool.Stop()
}

func TestCalculateSummary(t *testing.T) {
	results := []ScanResult{
		{
			Findings: []Finding{
				{Severity: SeverityCritical},
				{Severity: SeverityHigh},
				{Severity: SeverityMedium},
			},
		},
		{
			Findings: []Finding{
				{Severity: SeverityLow},
				{Severity: SeverityInfo},
			},
		},
	}

	startTime := time.Now().Add(-1 * time.Second)
	summary := CalculateSummary(results, startTime)

	if summary.TotalTargets != 2 {
		t.Errorf("Expected 2 targets, got %d", summary.TotalTargets)
	}

	if summary.TotalFindings != 5 {
		t.Errorf("Expected 5 findings, got %d", summary.TotalFindings)
	}

	if summary.CriticalCount != 1 {
		t.Errorf("Expected 1 critical, got %d", summary.CriticalCount)
	}

	if summary.HighCount != 1 {
		t.Errorf("Expected 1 high, got %d", summary.HighCount)
	}

	if summary.MediumCount != 1 {
		t.Errorf("Expected 1 medium, got %d", summary.MediumCount)
	}
}

func TestDefaultScanConfig(t *testing.T) {
	config := DefaultScanConfig()

	if config.MaxWorkers != 10 {
		t.Errorf("Expected 10 workers, got %d", config.MaxWorkers)
	}

	if config.Timeout != 5*time.Minute {
		t.Errorf("Expected 5m timeout, got %v", config.Timeout)
	}

	if len(config.ExcludePatterns) == 0 {
		t.Error("Expected default exclude patterns")
	}
}
