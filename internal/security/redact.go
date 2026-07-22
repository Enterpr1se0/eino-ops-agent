package security

import (
	"regexp"
)

type Redactor struct {
	rules []redactionRule
}

type redactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

func NewRedactor() *Redactor {
	rules := []redactionRule{
		{regexp.MustCompile(`(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{4,}`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)((?:["']?\b(?:password|passwd|sudo_password|proxy_password|api[_-]?key|access[_-]?token|secret|client_secret)["']?)\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)(--(?:password|passwd|sudo-password|proxy-password|api[-_]?key|access[-_]?token|token|secret)(?:=|\s+))(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)`), `${1}[REDACTED]`},
		{regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`), `${1}[REDACTED]@`},
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), `[REDACTED]`},
		{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`), `[REDACTED]`},
		{regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`), `[REDACTED]`},
		{regexp.MustCompile(`-----BEGIN (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----[\s\S]*?-----END (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----`), `[REDACTED]`},
	}
	return &Redactor{rules: rules}
}

func (r *Redactor) Redact(input string) string {
	result := input
	for _, rule := range r.rules {
		result = rule.pattern.ReplaceAllString(result, rule.replacement)
	}
	return result
}
