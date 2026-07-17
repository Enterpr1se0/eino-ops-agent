package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"eino-ops-agent/internal/config"
)

type LogEntry struct {
	Time      time.Time      `json:"time"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Component string         `json:"component,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type LogFilter struct {
	Level     string
	Component string
	Query     string
	Limit     int
}

type Buffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	limit   int
}

var activeBuffer atomic.Pointer[Buffer]
var activeLevel atomic.Int64
var activeFile atomic.Pointer[string]

type loggerContextKey struct{}

func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, logger)
}

func FromContext(ctx context.Context) *slog.Logger {
	if ctx != nil {
		if logger, ok := ctx.Value(loggerContextKey{}).(*slog.Logger); ok && logger != nil {
			return logger
		}
	}
	return slog.Default()
}

func Configure(cfg config.Logging) error {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return err
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid log format %q: use text or json", cfg.Format)
	}
	if cfg.RecentLimit <= 0 {
		cfg.RecentLimit = 2000
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 20
	}
	if cfg.MaxBackups < 0 {
		cfg.MaxBackups = 0
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(level)
	activeLevel.Store(int64(level))
	logFile := cfg.File
	activeFile.Store(&logFile)
	options := &slog.HandlerOptions{Level: levelVar, AddSource: cfg.AddSource, ReplaceAttr: replaceSensitiveAttr}
	handlers := []slog.Handler{newHandler(os.Stderr, format, options)}
	if cfg.File != "" && cfg.File != "-" {
		file, err := newRotatingWriter(cfg.File, int64(cfg.MaxSizeMB)<<20, cfg.MaxBackups)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		handlers = append(handlers, slog.NewJSONHandler(file, options))
	}
	buffer := &Buffer{limit: cfg.RecentLimit}
	activeBuffer.Store(buffer)
	handlers = append(handlers, &bufferHandler{buffer: buffer, level: levelVar})
	logger := slog.New(slog.NewMultiHandler(handlers...)).With("service", "ops-agent")
	slog.SetDefault(logger)
	slog.SetLogLoggerLevel(level)
	return nil
}

func newHandler(writer io.Writer, format string, options *slog.HandlerOptions) slog.Handler {
	if format == "json" {
		return slog.NewJSONHandler(writer, options)
	}
	return slog.NewTextHandler(writer, options)
}

func Recent(filter LogFilter) []LogEntry {
	buffer := activeBuffer.Load()
	if buffer == nil {
		return []LogEntry{}
	}
	return buffer.recent(filter)
}

func Components() []string {
	buffer := activeBuffer.Load()
	if buffer == nil {
		return []string{}
	}
	buffer.mu.RLock()
	defer buffer.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, entry := range buffer.entries {
		if entry.Component != "" {
			seen[entry.Component] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for component := range seen {
		result = append(result, component)
	}
	sort.Strings(result)
	return result
}

func MinimumLevel() string {
	return strings.ToLower(slog.Level(activeLevel.Load()).String())
}

func File() string {
	value := activeFile.Load()
	if value == nil || *value == "-" {
		return ""
	}
	return *value
}

func parseLevel(value string) (slog.Level, error) {
	var level slog.Level
	if strings.TrimSpace(value) == "" {
		return slog.LevelInfo, nil
	}
	if err := level.UnmarshalText([]byte(value)); err != nil {
		return 0, fmt.Errorf("invalid log level %q: use debug, info, warn, or error", value)
	}
	return level, nil
}

func replaceSensitiveAttr(_ []string, attr slog.Attr) slog.Attr {
	if sensitiveKey(attr.Key) {
		return slog.String(attr.Key, "[REDACTED]")
	}
	return attr
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(key)
	for _, suffix := range []string{"_bytes", "_count", "_segments"} {
		if strings.HasSuffix(key, suffix) {
			return false
		}
	}
	for _, fragment := range []string{"password", "secret", "token", "authorization", "api_key", "apikey", "private_key", "request_body", "response_body", "stdout", "stderr", "reasoning", "content"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

type bufferHandler struct {
	buffer *Buffer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

func (h *bufferHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *bufferHandler) Handle(_ context.Context, record slog.Record) error {
	fields := make(map[string]any, len(h.attrs)+record.NumAttrs())
	for _, attr := range h.attrs {
		appendAttr(fields, h.groups, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		appendAttr(fields, h.groups, attr)
		return true
	})
	component, _ := fields["component"].(string)
	delete(fields, "component")
	delete(fields, "service")
	h.buffer.add(LogEntry{Time: record.Time.UTC(), Level: strings.ToLower(record.Level.String()), Message: record.Message, Component: component, Fields: fields})
	return nil
}

func (h *bufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.groups = append(append([]string{}, h.groups...), name)
	return &clone
}

func appendAttr(fields map[string]any, groups []string, attr slog.Attr) {
	if attr.Equal(slog.Attr{}) {
		return
	}
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		next := groups
		if attr.Key != "" {
			next = append(append([]string{}, groups...), attr.Key)
		}
		for _, child := range value.Group() {
			appendAttr(fields, next, child)
		}
		return
	}
	key := strings.Join(append(append([]string{}, groups...), attr.Key), ".")
	if sensitiveKey(key) {
		fields[key] = "[REDACTED]"
		return
	}
	fields[key] = logValue(value)
}

func logValue(value slog.Value) any {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindBool:
		return value.Bool()
	case slog.KindDuration:
		return value.Duration().String()
	case slog.KindFloat64:
		return value.Float64()
	case slog.KindInt64:
		return value.Int64()
	case slog.KindTime:
		return value.Time().UTC()
	case slog.KindUint64:
		return value.Uint64()
	case slog.KindAny:
		if err, ok := value.Any().(error); ok {
			return err.Error()
		}
		if _, err := json.Marshal(value.Any()); err != nil {
			return fmt.Sprint(value.Any())
		}
		return value.Any()
	default:
		return value.String()
	}
}

func (b *Buffer) add(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		b.limit = 2000
	}
	if len(b.entries) == b.limit {
		copy(b.entries, b.entries[1:])
		b.entries[len(b.entries)-1] = entry
		return
	}
	b.entries = append(b.entries, entry)
}

func (b *Buffer) recent(filter LogFilter) []LogEntry {
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	minimum, err := parseLevel(filter.Level)
	if err != nil {
		minimum = slog.LevelDebug
	}
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	component := strings.ToLower(strings.TrimSpace(filter.Component))
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]LogEntry, 0, min(limit, len(b.entries)))
	for index := len(b.entries) - 1; index >= 0 && len(result) < limit; index-- {
		entry := b.entries[index]
		entryLevel, _ := parseLevel(entry.Level)
		if entryLevel < minimum || (component != "" && strings.ToLower(entry.Component) != component) {
			continue
		}
		if query != "" {
			encoded, _ := json.Marshal(entry.Fields)
			haystack := strings.ToLower(entry.Message + " " + entry.Component + " " + string(encoded))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		result = append(result, entry)
	}
	return result
}

type rotatingWriter struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
}

func newRotatingWriter(path string, maxBytes int64, maxBackups int) (*rotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	writer := &rotatingWriter{path: path, maxBytes: maxBytes, maxBackups: maxBackups}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *rotatingWriter) open() error {
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	w.file = file
	w.size = info.Size()
	return nil
}

func (w *rotatingWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.maxBytes > 0 && w.size > 0 && w.size+int64(len(data)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	written, err := w.file.Write(data)
	w.size += int64(written)
	return written, err
}

func (w *rotatingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	if w.maxBackups == 0 {
		_ = os.Remove(w.path)
	} else {
		_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxBackups))
		for index := w.maxBackups - 1; index >= 1; index-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", w.path, index), fmt.Sprintf("%s.%d", w.path, index+1))
		}
		if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return w.open()
}
