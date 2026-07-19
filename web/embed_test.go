package webui

import (
	"bytes"
	"io/fs"
	"testing"
)

func TestAssetsIncludeFrontend(t *testing.T) {
	index, err := fs.ReadFile(Assets(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(index, []byte(`id="root"`)) {
		t.Fatalf("embedded index.html does not contain the React root")
	}
}
