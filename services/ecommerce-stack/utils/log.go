package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

func NewLogger(serviceName string, environment string) *slog.Logger {
	level := slog.LevelInfo
	if environment == "development" {
		level = slog.LevelDebug
	}

	handlerOptions := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	logFormat := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_FORMAT")))
	if logFormat == "" && environment == "development" {
		logFormat = "pretty"
	}
	if logFormat == "pretty" {
		handler = NewPrettyHandler(os.Stdout, handlerOptions)
	} else if logFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, handlerOptions)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, handlerOptions)
	}

	return slog.New(handler).With(
		"service", serviceName,
		"component", "grpc",
	)
}

type PrettyHandler struct {
	mu     *sync.Mutex
	out    *os.File
	opts   *slog.HandlerOptions
	attrs  []slog.Attr
	groups []string
}

func NewPrettyHandler(out *os.File, opts *slog.HandlerOptions) *PrettyHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}

	return &PrettyHandler{
		mu:   &sync.Mutex{},
		out:  out,
		opts: opts,
	}
}

func (h *PrettyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.opts.Level == nil {
		return true
	}

	return level >= h.opts.Level.Level()
}

func (h *PrettyHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make([]slog.Attr, 0, len(h.attrs)+record.NumAttrs())
	attrs = append(attrs, h.attrs...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, h.groupAttr(attr))
		return true
	})

	service, attrs := takeAttr(attrs, "service")
	component, attrs := takeAttr(attrs, "component")

	line := fmt.Sprintf(
		"[%s] %s (%d)",
		record.Time.Format("15:04:05.000"),
		colorLevel(record.Level),
		os.Getpid(),
	)
	if service != "" || component != "" {
		line += fmt.Sprintf(" [%s]", strings.Trim(strings.Join([]string{service, component}, "/"), "/"))
	}
	line += fmt.Sprintf(": %s", record.Message)

	var builder strings.Builder
	builder.WriteString(line)
	builder.WriteByte('\n')

	for _, attr := range attrs {
		writePrettyAttr(&builder, attr, 2)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.WriteString(builder.String())
	return err
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(slicesClone(h.attrs), attrs...)
	return &next
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	if strings.TrimSpace(name) == "" {
		return h
	}

	next := *h
	next.groups = append(slicesClone(h.groups), name)
	return &next
}

func (h *PrettyHandler) groupAttr(attr slog.Attr) slog.Attr {
	if len(h.groups) == 0 {
		return attr
	}

	for i := len(h.groups) - 1; i >= 0; i-- {
		attr = slog.Group(h.groups[i], attr)
	}
	return attr
}

func takeAttr(attrs []slog.Attr, key string) (string, []slog.Attr) {
	remaining := attrs[:0]
	value := ""
	for _, attr := range attrs {
		attr.Value = attr.Value.Resolve()
		if attr.Key == key {
			value = fmt.Sprint(attrValue(attr.Value))
			continue
		}
		remaining = append(remaining, attr)
	}
	return value, remaining
}

func writePrettyAttr(builder *strings.Builder, attr slog.Attr, indent int) {
	attr.Value = attr.Value.Resolve()
	value := attrValue(attr.Value)
	padding := strings.Repeat(" ", indent)

	if isScalar(value) {
		builder.WriteString(fmt.Sprintf("%s%s: %v\n", padding, attr.Key, value))
		return
	}

	rendered, err := json.MarshalIndent(value, padding, "  ")
	if err != nil {
		builder.WriteString(fmt.Sprintf("%s%s: %v\n", padding, attr.Key, value))
		return
	}

	builder.WriteString(fmt.Sprintf("%s%s: %s\n", padding, attr.Key, rendered))
}

func attrValue(value slog.Value) any {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindBool:
		return value.Bool()
	case slog.KindInt64:
		return value.Int64()
	case slog.KindUint64:
		return value.Uint64()
	case slog.KindFloat64:
		return value.Float64()
	case slog.KindDuration:
		return value.Duration().String()
	case slog.KindTime:
		return value.Time().Format(time.RFC3339)
	case slog.KindGroup:
		group := map[string]any{}
		for _, attr := range value.Group() {
			attr.Value = attr.Value.Resolve()
			group[attr.Key] = attrValue(attr.Value)
		}
		return group
	default:
		raw := value.Any()
		if err, ok := raw.(error); ok {
			return err.Error()
		}
		return raw
	}
}

func isScalar(value any) bool {
	switch value.(type) {
	case string, bool, int, int64, uint64, float64, float32:
		return true
	default:
		return false
	}
}

func colorLevel(level slog.Level) string {
	label := level.String()
	if noColor() {
		return label
	}

	switch {
	case level >= slog.LevelError:
		return "\x1b[41;97m " + label + " \x1b[0m"
	case level >= slog.LevelWarn:
		return "\x1b[43;30m " + label + " \x1b[0m"
	case level <= slog.LevelDebug:
		return "\x1b[44;97m " + label + " \x1b[0m"
	default:
		return "\x1b[42;30m " + label + " \x1b[0m"
	}
}

func noColor() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_COLOR")))
	return os.Getenv("NO_COLOR") != "" || value == "0" || value == "false" || value == "off"
}

func slicesClone[T any](values []T) []T {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]T, len(values))
	copy(cloned, values)
	return cloned
}
