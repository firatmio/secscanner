// Package scanner provides secret detection capabilities.
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

// SecretScanner detects secrets and sensitive data in source code.
type SecretScanner struct {
	rules      []SecretRule
	entropy    bool
	entropyMin float64
}

// SecretRule defines a pattern for detecting secrets.
type SecretRule struct {
	ID          string         `json:"id" yaml:"id"`
	Name        string         `json:"name" yaml:"name"`
	Description string         `json:"description" yaml:"description"`
	Severity    Severity       `json:"severity" yaml:"severity"`
	Pattern     *regexp.Regexp `json:"-" yaml:"-"`
	PatternStr  string         `json:"pattern" yaml:"pattern"`
	Keywords    []string       `json:"keywords,omitempty" yaml:"keywords,omitempty"`
	Allowlist   []string       `json:"allowlist,omitempty" yaml:"allowlist,omitempty"`
	Remediation string         `json:"remediation" yaml:"remediation"`
}

// NewSecretScanner creates a new secret scanner with default rules.
func NewSecretScanner() *SecretScanner {
	scanner := &SecretScanner{
		entropy:    true,
		entropyMin: 4.5,
	}
	scanner.loadDefaultRules()
	return scanner
}

// Name returns the scanner's identifier.
func (s *SecretScanner) Name() string {
	return "secret-scanner"
}

// Description returns the scanner's description.
func (s *SecretScanner) Description() string {
	return "Detects secrets, API keys, tokens, and sensitive data in source code"
}

// SupportedTypes returns the target types this scanner supports.
func (s *SecretScanner) SupportedTypes() []TargetType {
	return []TargetType{TargetTypeFile}
}

// Scan performs secret detection on the target.
func (s *SecretScanner) Scan(ctx context.Context, target Target) ([]Finding, error) {
	var findings []Finding

	if len(target.Content) == 0 {
		return findings, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(target.Content))
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		lineNum++
		line := scanner.Text()

		for _, rule := range s.rules {
			// Skip if line doesn't contain keywords (optimization)
			if len(rule.Keywords) > 0 {
				hasKeyword := false
				lineLower := strings.ToLower(line)
				for _, kw := range rule.Keywords {
					if strings.Contains(lineLower, strings.ToLower(kw)) {
						hasKeyword = true
						break
					}
				}
				if !hasKeyword {
					continue
				}
			}

			matches := rule.Pattern.FindAllStringIndex(line, -1)
			for _, match := range matches {
				matchStr := line[match[0]:match[1]]

				// Check allowlist
				if s.isAllowlisted(matchStr, rule.Allowlist) {
					continue
				}

				// Mask the secret for display
				maskedMatch := s.maskSecret(matchStr)

				finding := Finding{
					ID:          s.generateFindingID(target.Path, lineNum, rule.ID),
					RuleID:      rule.ID,
					Title:       rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Type:        FindingTypeSecret,
					FilePath:    target.Path,
					StartLine:   lineNum,
					EndLine:     lineNum,
					Match:       maskedMatch,
					Remediation: rule.Remediation,
					Metadata: map[string]string{
						"rule_name": rule.Name,
						"category":  "secret",
					},
					Timestamp: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, scanner.Err()
}

// AddRule adds a custom secret detection rule.
func (s *SecretScanner) AddRule(rule SecretRule) error {
	if rule.Pattern == nil && rule.PatternStr != "" {
		compiled, err := regexp.Compile(rule.PatternStr)
		if err != nil {
			return fmt.Errorf("invalid pattern for rule %s: %w", rule.ID, err)
		}
		rule.Pattern = compiled
	}
	s.rules = append(s.rules, rule)
	return nil
}

// loadDefaultRules initializes the scanner with built-in secret patterns.
func (s *SecretScanner) loadDefaultRules() {
	defaultRules := []SecretRule{
		// AWS
		{
			ID:          "SEC001",
			Name:        "AWS Access Key ID",
			Description: "Detected AWS Access Key ID which could allow unauthorized access to AWS services",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
			Keywords:    []string{"AKIA", "aws", "amazon"},
			Remediation: "Rotate the AWS access key immediately and use IAM roles or environment variables instead",
		},
		{
			ID:          "SEC002",
			Name:        "AWS Secret Access Key",
			Description: "Detected AWS Secret Access Key which provides full access to AWS resources",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key[\s]*[=:]["']?([A-Za-z0-9/+=]{40})["']?`,
			Keywords:    []string{"aws", "secret", "key"},
			Remediation: "Rotate the AWS secret key immediately. Use AWS Secrets Manager or environment variables",
		},
		// GitHub
		{
			ID:          "SEC003",
			Name:        "GitHub Personal Access Token",
			Description: "Detected GitHub Personal Access Token which could allow repository access",
			Severity:    SeverityHigh,
			PatternStr:  `ghp_[A-Za-z0-9]{36}`,
			Keywords:    []string{"ghp_", "github"},
			Remediation: "Revoke the GitHub token immediately at github.com/settings/tokens",
		},
		{
			ID:          "SEC004",
			Name:        "GitHub OAuth Access Token",
			Description: "Detected GitHub OAuth Access Token",
			Severity:    SeverityHigh,
			PatternStr:  `gho_[A-Za-z0-9]{36}`,
			Keywords:    []string{"gho_", "github"},
			Remediation: "Revoke the GitHub OAuth token in your GitHub OAuth App settings",
		},
		{
			ID:          "SEC005",
			Name:        "GitHub App Token",
			Description: "Detected GitHub App Token",
			Severity:    SeverityHigh,
			PatternStr:  `(ghu|ghs)_[A-Za-z0-9]{36}`,
			Keywords:    []string{"ghu_", "ghs_", "github"},
			Remediation: "Rotate the GitHub App installation token",
		},
		// Stripe
		{
			ID:          "SEC006",
			Name:        "Stripe API Key",
			Description: "Detected Stripe API Key which could allow payment processing access",
			Severity:    SeverityCritical,
			PatternStr:  `(?i)(sk|pk)_(test|live)_[A-Za-z0-9]{24,}`,
			Keywords:    []string{"sk_", "pk_", "stripe"},
			Remediation: "Rotate the Stripe API key at dashboard.stripe.com/apikeys",
		},
		// Google
		{
			ID:          "SEC007",
			Name:        "Google API Key",
			Description: "Detected Google API Key",
			Severity:    SeverityHigh,
			PatternStr:  `AIza[0-9A-Za-z\-_]{35}`,
			Keywords:    []string{"AIza", "google", "api"},
			Remediation: "Rotate the Google API key in Google Cloud Console",
		},
		{
			ID:          "SEC008",
			Name:        "Google OAuth Client Secret",
			Description: "Detected Google OAuth Client Secret",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)client[_\-]?secret["'\s]*[:=]["'\s]*[A-Za-z0-9_\-]{24}`,
			Keywords:    []string{"client_secret", "google", "oauth"},
			Remediation: "Rotate the OAuth client secret in Google Cloud Console",
		},
		// Slack
		{
			ID:          "SEC009",
			Name:        "Slack Bot Token",
			Description: "Detected Slack Bot Token",
			Severity:    SeverityHigh,
			PatternStr:  `xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}`,
			Keywords:    []string{"xoxb", "slack"},
			Remediation: "Regenerate the Slack bot token in your Slack App settings",
		},
		{
			ID:          "SEC010",
			Name:        "Slack Webhook URL",
			Description: "Detected Slack Webhook URL",
			Severity:    SeverityMedium,
			PatternStr:  `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`,
			Keywords:    []string{"hooks.slack.com", "webhook"},
			Remediation: "Regenerate the Slack webhook URL in your Slack App settings",
		},
		// Private Keys
		{
			ID:          "SEC011",
			Name:        "RSA Private Key",
			Description: "Detected RSA Private Key",
			Severity:    SeverityCritical,
			PatternStr:  `-----BEGIN RSA PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN RSA PRIVATE KEY"},
			Remediation: "Remove the private key from source code and use secure key management",
		},
		{
			ID:          "SEC012",
			Name:        "SSH Private Key",
			Description: "Detected SSH Private Key",
			Severity:    SeverityCritical,
			PatternStr:  `-----BEGIN (OPENSSH|EC|DSA|PGP) PRIVATE KEY-----`,
			Keywords:    []string{"BEGIN", "PRIVATE KEY"},
			Remediation: "Remove the private key from source code and use secure key management",
		},
		// JWT
		{
			ID:          "SEC013",
			Name:        "JSON Web Token",
			Description: "Detected JSON Web Token (JWT)",
			Severity:    SeverityMedium,
			PatternStr:  `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`,
			Keywords:    []string{"eyJ", "jwt", "token"},
			Allowlist:   []string{"example", "test", "sample"},
			Remediation: "Remove JWT from source code. Use short-lived tokens and secure storage",
		},
		// Generic
		{
			ID:          "SEC014",
			Name:        "Generic API Key",
			Description: "Detected potential API key or secret",
			Severity:    SeverityMedium,
			PatternStr:  `(?i)(api[_\-]?key|apikey|api[_\-]?secret)[\s]*[=:]["']?[A-Za-z0-9_\-]{20,}["']?`,
			Keywords:    []string{"api_key", "apikey", "api-key", "api_secret"},
			Remediation: "Move API keys to environment variables or a secrets manager",
		},
		{
			ID:          "SEC015",
			Name:        "Password in Code",
			Description: "Detected hardcoded password",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)(password|passwd|pwd)[\s]*[=:]["'][^"']{8,}["']`,
			Keywords:    []string{"password", "passwd", "pwd"},
			Allowlist:   []string{"example", "test", "sample", "placeholder", "changeme"},
			Remediation: "Never hardcode passwords. Use environment variables or a secrets manager",
		},
		// Database
		{
			ID:          "SEC016",
			Name:        "Database Connection String",
			Description: "Detected database connection string with credentials",
			Severity:    SeverityHigh,
			PatternStr:  `(?i)(mysql|postgres|postgresql|mongodb|redis|mssql):\/\/[^:]+:[^@]+@[^\/]+`,
			Keywords:    []string{"mysql://", "postgres://", "mongodb://", "redis://"},
			Remediation: "Move database credentials to environment variables or a secrets manager",
		},
		// Twilio
		{
			ID:          "SEC017",
			Name:        "Twilio API Key",
			Description: "Detected Twilio API Key",
			Severity:    SeverityHigh,
			PatternStr:  `SK[a-f0-9]{32}`,
			Keywords:    []string{"twilio", "SK"},
			Remediation: "Rotate the Twilio API key at twilio.com/console",
		},
		// SendGrid
		{
			ID:          "SEC018",
			Name:        "SendGrid API Key",
			Description: "Detected SendGrid API Key",
			Severity:    SeverityHigh,
			PatternStr:  `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
			Keywords:    []string{"sendgrid", "SG."},
			Remediation: "Rotate the SendGrid API key at sendgrid.com/docs/ui/account-and-settings",
		},
		// npm
		{
			ID:          "SEC019",
			Name:        "npm Token",
			Description: "Detected npm authentication token",
			Severity:    SeverityHigh,
			PatternStr:  `npm_[A-Za-z0-9]{36}`,
			Keywords:    []string{"npm_", "npm"},
			Remediation: "Rotate the npm token at npmjs.com/settings/tokens",
		},
		// Discord
		{
			ID:          "SEC020",
			Name:        "Discord Bot Token",
			Description: "Detected Discord Bot Token",
			Severity:    SeverityHigh,
			PatternStr:  `[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`,
			Keywords:    []string{"discord", "bot", "token"},
			Remediation: "Regenerate the Discord bot token at discord.com/developers",
		},
	}

	for _, rule := range defaultRules {
		compiled, err := regexp.Compile(rule.PatternStr)
		if err != nil {
			continue
		}
		rule.Pattern = compiled
		s.rules = append(s.rules, rule)
	}
}

// isAllowlisted checks if a match should be ignored.
func (s *SecretScanner) isAllowlisted(match string, allowlist []string) bool {
	matchLower := strings.ToLower(match)
	for _, allowed := range allowlist {
		if strings.Contains(matchLower, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

// maskSecret masks sensitive parts of a secret for display.
func (s *SecretScanner) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// generateFindingID creates a unique identifier for a finding.
func (s *SecretScanner) generateFindingID(path string, line int, ruleID string) string {
	data := fmt.Sprintf("%s:%d:%s", path, line, ruleID)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// GetRules returns all configured rules.
func (s *SecretScanner) GetRules() []SecretRule {
	return s.rules
}

// SetEntropyCheck enables or disables entropy-based detection.
func (s *SecretScanner) SetEntropyCheck(enabled bool, minEntropy float64) {
	s.entropy = enabled
	s.entropyMin = minEntropy
}

// calculateEntropy calculates the Shannon entropy of a string.
func (s *SecretScanner) calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range str {
		freq[c]++
	}

	var entropy float64
	length := float64(len(str))
	for _, count := range freq {
		p := count / length
		entropy -= p * (logBase2(p))
	}

	return entropy
}

// logBase2 calculates log base 2.
func logBase2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	return ln(x) / ln(2)
}

// Simple natural log approximation for entropy calculation
func ln(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Using Taylor series approximation
	n := 0.0
	for x >= 2 {
		x /= 2
		n++
	}
	x--
	result := 0.0
	term := x
	for i := 1; i <= 100; i++ {
		if i%2 == 1 {
			result += term / float64(i)
		} else {
			result -= term / float64(i)
		}
		term *= x
	}
	return result + n*0.693147180559945
}
