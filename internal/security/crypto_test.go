package security

import (
	"strings"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	encryptor, err := NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("sensitive command output")
	ciphertext, err := encryptor.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, string(plain)) {
		t.Fatal("ciphertext contains plaintext")
	}
	decoded, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(plain) {
		t.Fatalf("got %q", decoded)
	}
}

func TestRedactor(t *testing.T) {
	redactor := NewRedactor()
	awsFixture := "AKIA" + "1234567890ABCDEF"
	input := "Authorization: Bearer abc.def.ghi\npassword=hunter2\n" + awsFixture
	output := redactor.Redact(input)
	for _, secret := range []string{"abc.def.ghi", "hunter2", awsFixture} {
		if strings.Contains(output, secret) {
			t.Fatalf("secret %q was not redacted: %s", secret, output)
		}
	}
}

func TestRedactorCoversStructuredCLIAndURLCredentials(t *testing.T) {
	redactor := NewRedactor()
	secrets := []string{"json-secret", "basic-token", "cli-secret", "proxy-secret", "query-secret"}
	input := `request failed: {"password":"json-secret"} Basic basic-token --api-key cli-secret https://user:proxy-secret@proxy.example?access_token=query-secret`
	output := redactor.Redact(input)
	for _, secret := range secrets {
		if strings.Contains(output, secret) {
			t.Fatalf("redaction leaked %q: %s", secret, output)
		}
	}
}
