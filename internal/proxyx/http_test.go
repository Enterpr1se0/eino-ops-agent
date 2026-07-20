package proxyx

import "testing"

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "http://127.0.0.1:7890", want: "http://127.0.0.1:7890"},
		{input: "HTTPS://proxy.example:8443/", want: "https://proxy.example:8443"},
		{input: "socks5://127.0.0.1:1080", want: "socks5://127.0.0.1:1080"},
		{input: "SOCKS5H://proxy.example:1080", want: "socks5h://proxy.example:1080"},
	}
	for _, test := range tests {
		got, err := NormalizeURL(test.input)
		if err != nil || got != test.want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, input := range []string{
		"ftp://proxy.example:21", "http://user:password@proxy.example", "http://proxy.example/path", "proxy.example:8080",
	} {
		if _, err := NormalizeURL(input); err == nil {
			t.Errorf("NormalizeURL(%q) accepted an invalid proxy URL", input)
		}
	}
}
