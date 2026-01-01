// Package scanner provides misconfiguration detection for Docker and Kubernetes.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// MisconfigScanner detects security misconfigurations in Docker and Kubernetes files.
type MisconfigScanner struct {
	dockerRules     []MisconfigRule
	kubernetesRules []MisconfigRule
}

// MisconfigRule defines a misconfiguration detection rule.
type MisconfigRule struct {
	ID          string                                                         `json:"id" yaml:"id"`
	Name        string                                                         `json:"name" yaml:"name"`
	Description string                                                         `json:"description" yaml:"description"`
	Severity    Severity                                                       `json:"severity" yaml:"severity"`
	Pattern     *regexp.Regexp                                                 `json:"-" yaml:"-"`
	PatternStr  string                                                         `json:"pattern" yaml:"pattern"`
	FileTypes   []string                                                       `json:"file_types" yaml:"file_types"`
	Remediation string                                                         `json:"remediation" yaml:"remediation"`
	CheckFunc   func(content string, line string, lineNum int) *MisconfigMatch `json:"-" yaml:"-"`
}

// MisconfigMatch represents a detected misconfiguration.
type MisconfigMatch struct {
	Line       int
	Content    string
	Suggestion string
}

// NewMisconfigScanner creates a new misconfiguration scanner with default rules.
func NewMisconfigScanner() *MisconfigScanner {
	scanner := &MisconfigScanner{}
	scanner.loadDockerRules()
	scanner.loadKubernetesRules()
	return scanner
}

// Name returns the scanner's identifier.
func (s *MisconfigScanner) Name() string {
	return "misconfig-scanner"
}

// Description returns the scanner's description.
func (s *MisconfigScanner) Description() string {
	return "Detects security misconfigurations in Dockerfiles and Kubernetes manifests"
}

// SupportedTypes returns the target types this scanner supports.
func (s *MisconfigScanner) SupportedTypes() []TargetType {
	return []TargetType{TargetTypeFile}
}

// Scan performs misconfiguration detection on the target.
func (s *MisconfigScanner) Scan(ctx context.Context, target Target) ([]Finding, error) {
	var findings []Finding

	if len(target.Content) == 0 {
		return findings, nil
	}

	// Determine file type
	isDockerfile := s.isDockerfile(target.Path)
	isKubernetes := s.isKubernetesManifest(target.Path, target.Content)

	if !isDockerfile && !isKubernetes {
		return findings, nil
	}

	contentStr := string(target.Content)
	scanner := bufio.NewScanner(bytes.NewReader(target.Content))
	lineNum := 0

	var rules []MisconfigRule
	if isDockerfile {
		rules = s.dockerRules
	} else if isKubernetes {
		rules = s.kubernetesRules
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()

		for _, rule := range rules {
			var match *MisconfigMatch

			if rule.CheckFunc != nil {
				match = rule.CheckFunc(contentStr, line, lineNum)
			} else if rule.Pattern != nil && rule.Pattern.MatchString(line) {
				match = &MisconfigMatch{
					Line:    lineNum,
					Content: strings.TrimSpace(line),
				}
			}

			if match != nil {
				finding := Finding{
					ID:          s.generateFindingID(target.Path, match.Line, rule.ID),
					RuleID:      rule.ID,
					Title:       rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Type:        FindingTypeMisconfiguration,
					FilePath:    target.Path,
					StartLine:   match.Line,
					EndLine:     match.Line,
					Match:       match.Content,
					Remediation: rule.Remediation,
					Metadata: map[string]string{
						"rule_name": rule.Name,
						"category":  "misconfiguration",
					},
					Timestamp: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	// Run full-content checks for Kubernetes
	if isKubernetes {
		findings = append(findings, s.runKubernetesFullChecks(ctx, target, contentStr)...)
	}

	return findings, scanner.Err()
}

// loadDockerRules initializes Docker-specific misconfiguration rules.
func (s *MisconfigScanner) loadDockerRules() {
	s.dockerRules = []MisconfigRule{
		{
			ID:          "DOCKER001",
			Name:        "Running as Root User",
			Description: "Container runs as root user which increases the attack surface",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)^USER\s+root\s*$`,
			Remediation: "Create and use a non-root user: USER appuser",
		},
		{
			ID:          "DOCKER002",
			Name:        "Using Latest Tag",
			Description: "Using 'latest' tag makes builds non-reproducible and unpredictable",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)^FROM\s+\S+:latest\s*$`,
			Remediation: "Pin to a specific image version: FROM image:1.2.3",
		},
		{
			ID:          "DOCKER003",
			Name:        "No Tag Specified",
			Description: "No image tag specified implies 'latest' which is unpredictable",
			Severity:    SeverityMedium,
			CheckFunc: func(content, line string, lineNum int) *MisconfigMatch {
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM ") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						image := parts[1]
						// Check if no tag and not a variable
						if !strings.Contains(image, ":") && !strings.Contains(image, "$") && !strings.Contains(image, "scratch") {
							return &MisconfigMatch{
								Line:    lineNum,
								Content: line,
							}
						}
					}
				}
				return nil
			},
			Remediation: "Specify a version tag: FROM image:version",
		},
		{
			ID:          "DOCKER004",
			Name:        "ADD Instead of COPY",
			Description: "ADD has extra features that can be exploited; use COPY for local files",
			Severity:    SeverityLow,
			PatternStr:  `(?i)^ADD\s+(?!https?://)\S+`,
			Remediation: "Use COPY instead of ADD for local files",
		},
		{
			ID:          "DOCKER005",
			Name:        "Secrets in Environment Variables",
			Description: "Sensitive data in ENV instructions is visible in image history",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)^ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY).*=`,
			Remediation: "Use Docker secrets or build-time arguments with --secret flag",
		},
		{
			ID:          "DOCKER006",
			Name:        "Curl/Wget Piped to Shell",
			Description: "Executing scripts from remote sources without verification is dangerous",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)(curl|wget)\s+.*\|\s*(sh|bash|zsh)`,
			Remediation: "Download scripts first, verify them, then execute",
		},
		{
			ID:          "DOCKER007",
			Name:        "apt-get without --no-install-recommends",
			Description: "Installing unnecessary packages increases image size and attack surface",
			Severity:    SeverityLow,
			PatternStr:  `apt-get\s+install(?!.*--no-install-recommends)`,
			Remediation: "Use: apt-get install --no-install-recommends",
		},
		{
			ID:          "DOCKER008",
			Name:        "Missing apt-get Clean",
			Description: "Leaving apt cache increases image size",
			Severity:    SeverityLow,
			CheckFunc: func(content, line string, lineNum int) *MisconfigMatch {
				if strings.Contains(line, "apt-get install") && !strings.Contains(content, "apt-get clean") && !strings.Contains(content, "rm -rf /var/lib/apt/lists") {
					return &MisconfigMatch{
						Line:    lineNum,
						Content: line,
					}
				}
				return nil
			},
			Remediation: "Add: && apt-get clean && rm -rf /var/lib/apt/lists/*",
		},
		{
			ID:          "DOCKER009",
			Name:        "HEALTHCHECK Not Defined",
			Description: "No HEALTHCHECK instruction found; container health won't be monitored",
			Severity:    SeverityMedium,
			CheckFunc: func(content, line string, lineNum int) *MisconfigMatch {
				// Only check once at the end
				if lineNum == 1 && !strings.Contains(strings.ToUpper(content), "HEALTHCHECK") {
					return &MisconfigMatch{
						Line:    1,
						Content: "No HEALTHCHECK instruction found",
					}
				}
				return nil
			},
			Remediation: "Add HEALTHCHECK instruction: HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
		},
		{
			ID:          "DOCKER010",
			Name:        "Privileged Port Exposed",
			Description: "Exposing privileged ports (< 1024) may require running as root",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)^EXPOSE\s+(2[0-3]|1?[0-9]{1,2}|[1-9][0-9]{2})\s*$`,
			Remediation: "Use unprivileged ports (>= 1024) when possible",
		},
		{
			ID:          "DOCKER011",
			Name:        "sudo Usage Detected",
			Description: "Using sudo in Dockerfile indicates running as non-root then escalating",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)\bsudo\b`,
			Remediation: "Run commands as needed user or use proper multi-stage builds",
		},
		{
			ID:          "DOCKER012",
			Name:        "Missing USER Instruction",
			Description: "No USER instruction found; container will run as root",
			Severity:    SeverityHigh,
			CheckFunc: func(content, line string, lineNum int) *MisconfigMatch {
				// Only check once at the end
				if lineNum == 1 && !strings.Contains(strings.ToUpper(content), "\nUSER ") {
					return &MisconfigMatch{
						Line:    1,
						Content: "No USER instruction found",
					}
				}
				return nil
			},
			Remediation: "Add USER instruction with non-root user: USER appuser",
		},
	}

	// Compile patterns
	for i := range s.dockerRules {
		if s.dockerRules[i].PatternStr != "" {
			s.dockerRules[i].Pattern, _ = regexp.Compile(s.dockerRules[i].PatternStr)
		}
	}
}

// loadKubernetesRules initializes Kubernetes-specific misconfiguration rules.
func (s *MisconfigScanner) loadKubernetesRules() {
	s.kubernetesRules = []MisconfigRule{
		{
			ID:          "K8S001",
			Name:        "Privileged Container",
			Description: "Container runs in privileged mode with full host access",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)privileged:\s*true`,
			Remediation: "Set privileged: false or remove the privileged field",
		},
		{
			ID:          "K8S002",
			Name:        "Running as Root",
			Description: "Container is configured to run as root user",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)runAsUser:\s*0\b`,
			Remediation: "Set runAsUser to a non-zero UID (e.g., runAsUser: 1000)",
		},
		{
			ID:          "K8S003",
			Name:        "Root Filesystem Not Read-Only",
			Description: "Container filesystem is writable which could allow tampering",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)readOnlyRootFilesystem:\s*false`,
			Remediation: "Set readOnlyRootFilesystem: true",
		},
		{
			ID:          "K8S004",
			Name:        "Privilege Escalation Allowed",
			Description: "Container allows privilege escalation",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)allowPrivilegeEscalation:\s*true`,
			Remediation: "Set allowPrivilegeEscalation: false",
		},
		{
			ID:          "K8S005",
			Name:        "Host Network Access",
			Description: "Pod uses host network namespace",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)hostNetwork:\s*true`,
			Remediation: "Set hostNetwork: false unless absolutely necessary",
		},
		{
			ID:          "K8S006",
			Name:        "Host PID Namespace",
			Description: "Pod uses host PID namespace allowing process snooping",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)hostPID:\s*true`,
			Remediation: "Set hostPID: false unless absolutely necessary",
		},
		{
			ID:          "K8S007",
			Name:        "Host IPC Namespace",
			Description: "Pod uses host IPC namespace",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)hostIPC:\s*true`,
			Remediation: "Set hostIPC: false unless absolutely necessary",
		},
		{
			ID:          "K8S008",
			Name:        "Dangerous Capabilities Added",
			Description: "Container has dangerous Linux capabilities",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)capabilities:[\s\S]*?add:[\s\S]*?(SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE)`,
			Remediation: "Remove dangerous capabilities or use minimal required capabilities",
		},
		{
			ID:          "K8S009",
			Name:        "No Resource Limits",
			Description: "Container has no resource limits which could cause DoS",
			Severity:    SeverityMedium,
			CheckFunc: func(content, line string, lineNum int) *MisconfigMatch {
				if strings.Contains(line, "containers:") && !strings.Contains(content, "limits:") {
					return &MisconfigMatch{
						Line:    lineNum,
						Content: "No resource limits defined",
					}
				}
				return nil
			},
			Remediation: "Define resources.limits for CPU and memory",
		},
		{
			ID:          "K8S010",
			Name:        "Latest Image Tag",
			Description: "Using 'latest' tag makes deployments unpredictable",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)image:\s*\S+:latest`,
			Remediation: "Use specific image tags for reproducible deployments",
		},
		{
			ID:          "K8S011",
			Name:        "Host Path Volume Mount",
			Description: "Mounting host path can expose sensitive host data",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)hostPath:`,
			Remediation: "Use persistent volumes instead of hostPath when possible",
		},
		{
			ID:          "K8S012",
			Name:        "Default Service Account",
			Description: "Using default service account may have unnecessary permissions",
			Severity:    SeverityLow,
			PatternStr:  `(?i)serviceAccountName:\s*default`,
			Remediation: "Create and use a dedicated service account with minimal permissions",
		},
		{
			ID:          "K8S013",
			Name:        "Secrets in Environment Variables",
			Description: "Secrets in env vars can be exposed in logs and process listings",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)env:[\s\S]*?valueFrom:[\s\S]*?secretKeyRef:`,
			Remediation: "Mount secrets as files instead of environment variables",
		},
		{
			ID:          "K8S014",
			Name:        "Missing Network Policy",
			Description: "No network policy restricting pod communication",
			Severity:    SeverityMedium,
			CheckFunc: func(content, line string, lineNum int) *MisconfigMatch {
				if strings.Contains(content, "kind: Deployment") && !strings.Contains(content, "kind: NetworkPolicy") {
					if lineNum == 1 {
						return &MisconfigMatch{
							Line:    1,
							Content: "No NetworkPolicy defined",
						}
					}
				}
				return nil
			},
			Remediation: "Define NetworkPolicy to restrict ingress and egress traffic",
		},
		{
			ID:          "K8S015",
			Name:        "Writable /proc Mount",
			Description: "Writable /proc mount can be used to escape container",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)procMount:\s*Unmasked`,
			Remediation: "Use default procMount (Masked) or explicitly set procMount: Default",
		},
	}

	// Compile patterns
	for i := range s.kubernetesRules {
		if s.kubernetesRules[i].PatternStr != "" {
			s.kubernetesRules[i].Pattern, _ = regexp.Compile(s.kubernetesRules[i].PatternStr)
		}
	}
}

// runKubernetesFullChecks runs checks that require full content analysis.
func (s *MisconfigScanner) runKubernetesFullChecks(ctx context.Context, target Target, content string) []Finding {
	var findings []Finding

	// Check for missing securityContext
	if strings.Contains(content, "containers:") && !strings.Contains(content, "securityContext:") {
		findings = append(findings, Finding{
			ID:          s.generateFindingID(target.Path, 1, "K8S016"),
			RuleID:      "K8S016",
			Title:       "Missing Security Context",
			Description: "No securityContext defined for pod or containers",
			Severity:    SeverityMedium,
			Type:        FindingTypeMisconfiguration,
			FilePath:    target.Path,
			StartLine:   1,
			EndLine:     1,
			Match:       "securityContext not found",
			Remediation: "Add securityContext with appropriate security settings",
			Metadata: map[string]string{
				"rule_name": "Missing Security Context",
				"category":  "misconfiguration",
			},
			Timestamp: time.Now(),
		})
	}

	// Check for runAsNonRoot
	if strings.Contains(content, "containers:") && !strings.Contains(content, "runAsNonRoot: true") {
		findings = append(findings, Finding{
			ID:          s.generateFindingID(target.Path, 1, "K8S017"),
			RuleID:      "K8S017",
			Title:       "RunAsNonRoot Not Set",
			Description: "runAsNonRoot is not explicitly set to true",
			Severity:    SeverityMedium,
			Type:        FindingTypeMisconfiguration,
			FilePath:    target.Path,
			StartLine:   1,
			EndLine:     1,
			Match:       "runAsNonRoot: true not found",
			Remediation: "Add runAsNonRoot: true in securityContext",
			Metadata: map[string]string{
				"rule_name": "RunAsNonRoot Not Set",
				"category":  "misconfiguration",
			},
			Timestamp: time.Now(),
		})
	}

	return findings
}

// isDockerfile checks if the file is a Dockerfile.
func (s *MisconfigScanner) isDockerfile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, "dockerfile") ||
		strings.Contains(lower, "dockerfile.") ||
		strings.HasSuffix(lower, ".dockerfile")
}

// isKubernetesManifest checks if the file is a Kubernetes manifest.
func (s *MisconfigScanner) isKubernetesManifest(path string, content []byte) bool {
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return false
	}

	// Check for Kubernetes API version marker
	contentStr := string(content)
	return strings.Contains(contentStr, "apiVersion:") &&
		(strings.Contains(contentStr, "kind:") ||
			strings.Contains(contentStr, "metadata:"))
}

// generateFindingID creates a unique identifier for a finding.
func (s *MisconfigScanner) generateFindingID(path string, line int, ruleID string) string {
	data := fmt.Sprintf("%s:%d:%s", path, line, ruleID)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// AddDockerRule adds a custom Docker misconfiguration rule.
func (s *MisconfigScanner) AddDockerRule(rule MisconfigRule) error {
	if rule.PatternStr != "" && rule.Pattern == nil {
		compiled, err := regexp.Compile(rule.PatternStr)
		if err != nil {
			return fmt.Errorf("invalid pattern for rule %s: %w", rule.ID, err)
		}
		rule.Pattern = compiled
	}
	s.dockerRules = append(s.dockerRules, rule)
	return nil
}

// AddKubernetesRule adds a custom Kubernetes misconfiguration rule.
func (s *MisconfigScanner) AddKubernetesRule(rule MisconfigRule) error {
	if rule.PatternStr != "" && rule.Pattern == nil {
		compiled, err := regexp.Compile(rule.PatternStr)
		if err != nil {
			return fmt.Errorf("invalid pattern for rule %s: %w", rule.ID, err)
		}
		rule.Pattern = compiled
	}
	s.kubernetesRules = append(s.kubernetesRules, rule)
	return nil
}
