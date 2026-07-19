package skills

import "strings"

type Skill struct {
	Name          string `json:"name"`
	Summary       string `json:"summary"`
	Enabled       bool   `json:"enabled"`
	Content       string `json:"content,omitempty"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
	FileCount     int    `json:"file_count,omitempty"`
	SizeBytes     int64  `json:"size_bytes,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

func firstParagraph(text string) string {
	parts := strings.Split(strings.TrimSpace(text), "\n\n")
	if len(parts) < 2 {
		return strings.TrimSpace(text)
	}
	return strings.Join(strings.Fields(parts[1]), " ")
}
