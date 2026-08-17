package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

func New(format, level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv, ReplaceAttr: redact}
	var h slog.Handler
	if strings.EqualFold(format, "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func Context(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, log)
}

func From(ctx context.Context) *slog.Logger {
	if v, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && v != nil {
		return v
	}
	return slog.Default()
}

type ctxKey struct{}

func redact(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	if sensitive(key) {
		return slog.String(a.Key, "[redacted]")
	}
	if a.Value.Kind() == slog.KindString && looksSecret(a.Value.String()) {
		return slog.String(a.Key, "[redacted]")
	}
	return a
}

func sensitive(key string) bool {
	switch {
	case strings.Contains(key, "token"):
		return true
	case strings.Contains(key, "authorization"):
		return true
	case strings.Contains(key, "password"):
		return true
	case strings.Contains(key, "secret"):
		return true
	case strings.Contains(key, "cookie"):
		return true
	case strings.Contains(key, "private"):
		return true
	case strings.Contains(key, "pem"):
		return true
	case key == "cert" || strings.HasSuffix(key, "_cert") || strings.HasSuffix(key, "_key"):
		return true
	default:
		return false
	}
}

func looksSecret(s string) bool {
	return strings.Contains(s, "BEGIN ") || strings.HasPrefix(s, "psg_tok_")
}
