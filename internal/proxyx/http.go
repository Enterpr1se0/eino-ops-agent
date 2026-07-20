package proxyx

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func NormalizeURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("invalid proxy URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
	parsed.Path = ""
	return parsed.String(), nil
}

func NewHTTPClient(proxyURL, username, password string, timeout time.Duration) (*http.Client, error) {
	normalized, err := NormalizeURL(proxyURL)
	if err != nil {
		return nil, err
	}
	if normalized == "" {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if username != "" {
		parsed.User = url.UserPassword(username, password)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(parsed)
	transport.ResponseHeaderTimeout = timeout
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
