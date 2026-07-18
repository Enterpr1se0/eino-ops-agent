package skills

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxSkillPackageBytes = 8 << 20
	maxSkillFileBytes    = 2 << 20
	maxSkillFiles        = 128
)

var (
	ErrNotFound = errors.New("skill not found")
	ErrDisabled = errors.New("skill is disabled")
	skillNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

const metadataFilename = "skill.json"

type metadata struct {
	Enabled bool `json:"enabled"`
}

// Registry stores administrator-managed skills as directories. Content is
// trusted as administrator-authored; validation here is limited to keeping the
// on-disk package structurally sound and inside the registry root.
type Registry struct {
	root       string
	initialize sync.Once
	initErr    error
	mu         sync.RWMutex
}

func NewRegistry(root string) *Registry {
	return &Registry{root: filepath.Clean(root)}
}

func (r *Registry) Root() string { return r.root }

func (r *Registry) List() ([]Skill, error) {
	if err := r.ensure(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries, err := os.ReadDir(r.root)
	if err != nil {
		return nil, err
	}
	result := make([]Skill, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !validSkillName(entry.Name()) {
			continue
		}
		skill, err := r.readUnlocked(entry.Name(), false)
		if err != nil {
			continue
		}
		result = append(result, skill)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (r *Registry) Get(name string) (Skill, error) {
	if err := r.ensure(); err != nil {
		return Skill{}, err
	}
	if !validSkillName(name) {
		return Skill{}, fmt.Errorf("invalid skill name")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.readUnlocked(name, true)
}

func (r *Registry) Save(name, skillContent string) (Skill, error) {
	if err := r.ensure(); err != nil {
		return Skill{}, err
	}
	name = strings.TrimSpace(name)
	if !validSkillName(name) {
		return Skill{}, fmt.Errorf("invalid skill name: use 1-64 letters, numbers, dots, underscores or hyphens")
	}
	data := []byte(skillContent)
	if len(bytes.TrimSpace(data)) == 0 {
		return Skill{}, fmt.Errorf("SKILL.md cannot be empty")
	}
	if len(data) > maxSkillFileBytes {
		return Skill{}, fmt.Errorf("SKILL.md exceeds 2 MiB")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	directory := filepath.Join(r.root, name)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Skill{}, err
	}
	if err := atomicWrite(filepath.Join(directory, "SKILL.md"), data); err != nil {
		return Skill{}, err
	}
	return r.readUnlocked(name, true)
}

func (r *Registry) SetEnabled(name string, enabled bool) (Skill, error) {
	if err := r.ensure(); err != nil {
		return Skill{}, err
	}
	if !validSkillName(name) {
		return Skill{}, fmt.Errorf("invalid skill name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.readUnlocked(name, false); err != nil {
		return Skill{}, err
	}
	payload, err := json.MarshalIndent(metadata{Enabled: enabled}, "", "  ")
	if err != nil {
		return Skill{}, err
	}
	payload = append(payload, '\n')
	if err := atomicWrite(filepath.Join(r.root, name, metadataFilename), payload); err != nil {
		return Skill{}, err
	}
	return r.readUnlocked(name, true)
}

func (r *Registry) Import(name, filename string, source io.Reader) (Skill, error) {
	if err := r.ensure(); err != nil {
		return Skill{}, err
	}
	name = strings.TrimSpace(name)
	if !validSkillName(name) {
		return Skill{}, fmt.Errorf("invalid skill name: use 1-64 letters, numbers, dots, underscores or hyphens")
	}
	data, err := io.ReadAll(io.LimitReader(source, maxSkillPackageBytes+1))
	if err != nil {
		return Skill{}, err
	}
	if len(data) > maxSkillPackageBytes {
		return Skill{}, fmt.Errorf("skill upload exceeds 8 MiB")
	}
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".md", ".markdown":
		return r.importMarkdown(name, data)
	case ".zip":
		return r.importZIP(name, data)
	default:
		return Skill{}, fmt.Errorf("skill upload must be a Markdown or ZIP file")
	}
}

func (r *Registry) importMarkdown(name string, data []byte) (Skill, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Skill{}, fmt.Errorf("SKILL.md cannot be empty")
	}
	if len(data) > maxSkillFileBytes {
		return Skill{}, fmt.Errorf("SKILL.md exceeds 2 MiB")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	temporary, err := os.MkdirTemp(r.root, ".skill-upload-")
	if err != nil {
		return Skill{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.WriteFile(filepath.Join(temporary, "SKILL.md"), data, 0o600); err != nil {
		return Skill{}, err
	}
	if err := replaceDirectory(filepath.Join(r.root, name), temporary); err != nil {
		return Skill{}, err
	}
	committed = true
	return r.readUnlocked(name, true)
}

func (r *Registry) Delete(name string) error {
	if err := r.ensure(); err != nil {
		return err
	}
	if !validSkillName(name) {
		return fmt.Errorf("invalid skill name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	target := filepath.Join(r.root, name)
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("invalid skill directory")
	}
	return os.RemoveAll(target)
}

func (r *Registry) ensure() error {
	r.initialize.Do(func() { r.initErr = r.initializeRoot() })
	return r.initErr
}

func (r *Registry) initializeRoot() error {
	if strings.TrimSpace(r.root) == "" || r.root == "." {
		return fmt.Errorf("skill registry root is not configured")
	}
	if info, err := os.Lstat(r.root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("skill registry root must be a real directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(r.root)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".skills-initialize-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	entries, err := content.ReadDir("content")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
			continue
		}
		data, err := content.ReadFile("content/" + entry.Name())
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(entry.Name(), ".md")
		directory := filepath.Join(temporary, name)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), data, 0o600); err != nil {
			return err
		}
	}
	if err := os.Rename(temporary, r.root); err != nil {
		if info, statErr := os.Lstat(r.root); statErr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	committed = true
	return nil
}

func (r *Registry) readUnlocked(name string, includeContent bool) (Skill, error) {
	directory := filepath.Join(r.root, name)
	mainPath := filepath.Join(directory, "SKILL.md")
	info, err := os.Lstat(mainPath)
	if errors.Is(err, os.ErrNotExist) {
		return Skill{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return Skill{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Skill{}, fmt.Errorf("skill %q has an invalid SKILL.md", name)
	}
	data, err := os.ReadFile(mainPath)
	if err != nil {
		return Skill{}, err
	}
	if len(data) > maxSkillFileBytes {
		return Skill{}, fmt.Errorf("skill %q SKILL.md exceeds 2 MiB", name)
	}
	digest := sha256.Sum256(data)
	skill := Skill{Name: name, Summary: firstParagraph(string(data)), Enabled: true, ContentSHA256: fmt.Sprintf("%x", digest), UpdatedAt: info.ModTime().UTC().Format(time.RFC3339Nano)}
	metadataPath := filepath.Join(directory, metadataFilename)
	if metadataData, metadataErr := os.ReadFile(metadataPath); metadataErr == nil {
		var saved metadata
		if err := json.Unmarshal(metadataData, &saved); err != nil {
			return Skill{}, fmt.Errorf("skill %q has invalid %s: %w", name, metadataFilename, err)
		}
		skill.Enabled = saved.Enabled
	} else if !errors.Is(metadataErr, os.ErrNotExist) {
		return Skill{}, metadataErr
	}
	if includeContent {
		skill.Content = string(data)
	}
	err = filepath.WalkDir(directory, func(currentPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("skill %q contains a symbolic link", name)
		}
		if entry.IsDir() {
			return nil
		}
		if currentPath == metadataPath {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		skill.FileCount++
		skill.SizeBytes += fileInfo.Size()
		if fileInfo.ModTime().UTC().Format(time.RFC3339Nano) > skill.UpdatedAt {
			skill.UpdatedAt = fileInfo.ModTime().UTC().Format(time.RFC3339Nano)
		}
		return nil
	})
	return skill, err
}

func (r *Registry) importZIP(name string, data []byte) (Skill, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Skill{}, fmt.Errorf("invalid skill ZIP: %w", err)
	}
	if len(reader.File) == 0 || len(reader.File) > maxSkillFiles {
		return Skill{}, fmt.Errorf("skill ZIP must contain 1-%d entries", maxSkillFiles)
	}
	mainFiles := make([]string, 0, 1)
	for _, file := range reader.File {
		clean, err := cleanZIPPath(file.Name)
		if err != nil {
			return Skill{}, err
		}
		if path.Base(clean) == "SKILL.md" {
			mainFiles = append(mainFiles, clean)
		}
	}
	if len(mainFiles) != 1 {
		return Skill{}, fmt.Errorf("skill ZIP must contain exactly one SKILL.md")
	}
	prefix := path.Dir(mainFiles[0])
	r.mu.Lock()
	defer r.mu.Unlock()
	temporary, err := os.MkdirTemp(r.root, ".skill-upload-")
	if err != nil {
		return Skill{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	var total int64
	for _, file := range reader.File {
		clean, err := cleanZIPPath(file.Name)
		if err != nil {
			return Skill{}, err
		}
		relative := clean
		if prefix != "." {
			if clean == prefix {
				continue
			}
			if !strings.HasPrefix(clean, prefix+"/") {
				continue
			}
			relative = strings.TrimPrefix(clean, prefix+"/")
		}
		if relative == "" {
			continue
		}
		if relative == metadataFilename {
			return Skill{}, fmt.Errorf("skill ZIP cannot contain reserved %s", metadataFilename)
		}
		if file.Mode()&os.ModeSymlink != 0 {
			return Skill{}, fmt.Errorf("skill ZIP cannot contain symbolic links")
		}
		target := filepath.Join(temporary, filepath.FromSlash(relative))
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return Skill{}, err
			}
			continue
		}
		if file.UncompressedSize64 > maxSkillFileBytes {
			return Skill{}, fmt.Errorf("skill file %q exceeds 2 MiB", relative)
		}
		total += int64(file.UncompressedSize64)
		if total > maxSkillPackageBytes {
			return Skill{}, fmt.Errorf("expanded skill ZIP exceeds 8 MiB")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return Skill{}, err
		}
		input, err := file.Open()
		if err != nil {
			return Skill{}, err
		}
		payload, readErr := io.ReadAll(io.LimitReader(input, maxSkillFileBytes+1))
		closeErr := input.Close()
		if readErr != nil {
			return Skill{}, readErr
		}
		if closeErr != nil {
			return Skill{}, closeErr
		}
		if len(payload) > maxSkillFileBytes {
			return Skill{}, fmt.Errorf("skill file %q exceeds 2 MiB", relative)
		}
		if err := os.WriteFile(target, payload, 0o600); err != nil {
			return Skill{}, err
		}
	}
	mainData, err := os.ReadFile(filepath.Join(temporary, "SKILL.md"))
	if err != nil || len(bytes.TrimSpace(mainData)) == 0 {
		return Skill{}, fmt.Errorf("skill ZIP has an empty or missing SKILL.md")
	}
	if err := replaceDirectory(filepath.Join(r.root, name), temporary); err != nil {
		return Skill{}, err
	}
	committed = true
	return r.readUnlocked(name, true)
}

func cleanZIPPath(value string) (string, error) {
	if value == "" || strings.Contains(value, `\`) || strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("skill ZIP contains an invalid path")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("skill ZIP contains a path outside its root")
	}
	return clean, nil
}

func replaceDirectory(target, replacement string) error {
	backup, err := os.MkdirTemp(filepath.Dir(target), ".skill-backup-")
	if err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(backup) }()
	hadTarget := false
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("existing skill target is invalid")
		}
		if err := os.Rename(target, backup); err != nil {
			return err
		}
		hadTarget = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(replacement, target); err != nil {
		if hadTarget {
			_ = os.Rename(backup, target)
		}
		return err
	}
	if hadTarget {
		_ = os.RemoveAll(backup)
	}
	return nil
}

func atomicWrite(target string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(target), ".SKILL.md-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, target)
}

func validSkillName(name string) bool { return skillNameRE.MatchString(name) }
