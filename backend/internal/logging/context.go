package logging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strings"

	"go.uber.org/zap"
)

type ctxKey struct{}

func WithLogger(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

func FromContext(ctx context.Context) Logger {
	if l, ok := ctx.Value(ctxKey{}).(Logger); ok && l != nil {
		return l
	}
	return NewNop()
}

func ctxFields(ctx context.Context) []Field {
	if ctx == nil {
		return nil
	}
	v := ctx.Value(fieldsKey{})
	if v == nil {
		return nil
	}
	fs, _ := v.([]Field)
	if len(fs) == 0 {
		return nil
	}
	out := make([]Field, len(fs))
	copy(out, fs)
	return out
}

type fieldsKey struct{}

// WithFields attaches zap fields to ctx so they are merged into every
// log line emitted via FromContext(ctx). Used to thread request-scoped
// fields (request_id, etc.) through code that doesn't own a *zap.Logger.
func WithFields(ctx context.Context, fields ...Field) context.Context {
	if len(fields) == 0 {
		return ctx
	}
	prev := ctxFields(ctx)
	merged := make([]Field, 0, len(prev)+len(fields))
	merged = append(merged, prev...)
	merged = append(merged, fields...)
	return context.WithValue(ctx, fieldsKey{}, merged)
}

// HashIP returns a stable, salted, irreversible hash of an IP for logs.
// Invalid IP strings are returned unchanged so they remain debuggable.
func HashIP(ip, salt string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return ip
	}
	h := sha256.Sum256([]byte(salt + ip))
	return hex.EncodeToString(h[:12])
}

func FieldForRequestID(rid string) Field { return zap.String("request_id", rid) }
