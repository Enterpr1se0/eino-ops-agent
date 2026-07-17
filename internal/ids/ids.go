package ids

import (
	"crypto/rand"
	"encoding/hex"
)

func New(prefix string) string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(buf)
}
