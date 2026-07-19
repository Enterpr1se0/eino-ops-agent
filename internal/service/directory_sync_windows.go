//go:build windows

package service

// Windows does not expose portable directory fsync semantics through os.File.
// File contents are synced before every rename or hard-link that reaches here.
func syncLocalDirectory(string) error {
	return nil
}
