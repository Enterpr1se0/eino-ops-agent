package security

import (
	"regexp"
	"strings"
)

type Redactor struct {
	patterns []*regexp.Regexp
}

func NewRedactor() *Redactor {
	expressions := []string{
		`(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+`,
		`(?i)((?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[=:]\s*)[^\s,;]+`,
		`AKIA[0-9A-Z]{16}`,
		`gh[pousr]_[A-Za-z0-9]{20,}`,
		`sk-[A-Za-z0-9_-]{16,}`,
		`-----BEGIN (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----[\s\S]*?-----END (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----`,
	}
	patterns := make([]*regexp.Regexp, 0, len(expressions))
	for _, expression := range expressions {
		patterns = append(patterns, regexp.MustCompile(expression))
	}
	return &Redactor{patterns: patterns}
}

func (r *Redactor) Redact(input string) string {
	result := input
	for _, pattern := range r.patterns {
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			if index := strings.IndexAny(match, "=:"); index >= 0 && !strings.Contains(match[:index], "PRIVATE KEY") {
				return match[:index+1] + "[REDACTED]"
			}
			if index := strings.Index(strings.ToLower(match), "bearer "); index >= 0 {
				return match[:index+7] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return result
}
