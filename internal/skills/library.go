package skills

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed content/*.md
var content embed.FS

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

func List() ([]Skill, error) {
	entries, err := content.ReadDir("content")
	if err != nil {
		return nil, err
	}
	result := make([]Skill, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
			continue
		}
		data, err := content.ReadFile("content/" + entry.Name())
		if err != nil {
			return nil, err
		}
		text := string(data)
		result = append(result, Skill{Name: strings.TrimSuffix(entry.Name(), ".md"), Summary: firstParagraph(text), Enabled: true})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func Get(name string) (Skill, error) {
	if strings.ContainsAny(name, `/\\`) || name == "" {
		return Skill{}, fmt.Errorf("invalid skill name")
	}
	data, err := content.ReadFile("content/" + name + ".md")
	if err != nil {
		return Skill{}, fmt.Errorf("skill %q not found", name)
	}
	text := string(data)
	digest := sha256.Sum256(data)
	return Skill{Name: name, Summary: firstParagraph(text), Enabled: true, Content: text, ContentSHA256: fmt.Sprintf("%x", digest), FileCount: 1, SizeBytes: int64(len(data))}, nil
}

func firstParagraph(text string) string {
	parts := strings.Split(strings.TrimSpace(text), "\n\n")
	if len(parts) < 2 {
		return strings.TrimSpace(text)
	}
	return strings.Join(strings.Fields(parts[1]), " ")
}
