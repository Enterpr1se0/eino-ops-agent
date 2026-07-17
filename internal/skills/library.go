package skills

import (
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed content/*.md
var content embed.FS

type Skill struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Content string `json:"content,omitempty"`
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
		result = append(result, Skill{Name: strings.TrimSuffix(entry.Name(), ".md"), Summary: firstParagraph(text)})
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
	return Skill{Name: name, Summary: firstParagraph(text), Content: text}, nil
}

func firstParagraph(text string) string {
	parts := strings.Split(strings.TrimSpace(text), "\n\n")
	if len(parts) < 2 {
		return strings.TrimSpace(text)
	}
	return strings.Join(strings.Fields(parts[1]), " ")
}
