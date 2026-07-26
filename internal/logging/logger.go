// logging wraps zap behind a small interface so the rest of the codebase
// depends on logging.Logger, not zap directly. This lets us swap to slog
// or another backend without rewriting call sites.
package logging

import (
	"context"
	"errors"
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is context-aware so request-scaped fields like request_id can
// flow through ctx.
type Logger interface {
	Debug(ctx context.Context, msg string, fields ...Field)
	Info(ctx context.Context, msg string, fields ...Field)
	Warn(ctx context.Context, msg string, fields ...Field)
	Error(ctx context.Context, msg string, fields ...Field)
	With(fields ...Field) Logger
	Sync() error
}

type Field = zap.Field

func String(k, v string) Field      { return zap.String(k, v) }
func Int(k string, v int) Field     { return zap.Int(k, v) }
func Int64(k string, v int64) Field { return zap.Int64(k, v) }
func Bool(k string, v bool) Field   { return zap.Bool(k, v) }
func Any(k string, v any) Field     { return zap.Any(k, v) }
func Err(err error) Field           { return zap.Error(err) }

type zapLogger struct {
	z          *zap.Logger
	fields     []Field
	callerSkip int
}

func New(level, format string) (Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}

	ec := zap.NewProductionEncoderConfig()
	ec.EncodeTime = zapcore.ISO8601TimeEncoder
	ec.EncodeDuration = zapcore.StringDurationEncoder

	var enc zapcore.Encoder
	switch format {
	case "console":
		ec.EncodeLevel = zapcore.CapitalColorLevelEncoder
		enc = zapcore.NewConsoleEncoder(ec)
	case "json", "":
		enc = zapcore.NewJSONEncoder(ec)
	default:
		return nil, unknownFormatError{format: format}
	}

	core := zapcore.NewCore(enc, zapcore.AddSync(os.Stderr), lvl)
	// callerSkip=1 so caller info points to our wrapper caller.
	z := zap.New(core, zap.AddCallerSkip(1))
	return &zapLogger{z: z, callerSkip: 1}, nil
}

func NewFromZap(z *zap.Logger) Logger {
	return &zapLogger{z: z, callerSkip: 1}
}

func NewNop() Logger { return &zapLogger{z: zap.NewNop()} }

func (l *zapLogger) emit(ctx context.Context, lvl zapcore.Level, msg string, fields []Field) {
	if !l.z.Core().Enabled(lvl) {
		return
	}
	all := make([]Field, 0, len(l.fields)+2+len(fields))
	all = append(all, l.fields...)
	all = append(all, ctxFields(ctx)...)
	all = append(all, fields...)
	if ce := l.z.Check(lvl, msg); ce != nil {
		ce.Write(all...)
	} else {
		_ = all
	}
}

func (l *zapLogger) Debug(ctx context.Context, msg string, fields ...Field) {
	l.emit(ctx, zapcore.DebugLevel, msg, fields)
}
func (l *zapLogger) Info(ctx context.Context, msg string, fields ...Field) {
	l.emit(ctx, zapcore.InfoLevel, msg, fields)
}
func (l *zapLogger) Warn(ctx context.Context, msg string, fields ...Field) {
	l.emit(ctx, zapcore.WarnLevel, msg, fields)
}
func (l *zapLogger) Error(ctx context.Context, msg string, fields ...Field) {
	l.emit(ctx, zapcore.ErrorLevel, msg, fields)
}

func (l *zapLogger) With(fields ...Field) Logger {
	combined := make([]Field, 0, len(l.fields)+len(fields))
	combined = append(combined, l.fields...)
	combined = append(combined, fields...)
	return &zapLogger{z: l.z, fields: combined, callerSkip: l.callerSkip}
}

func (l *zapLogger) Sync() error {
	if l.z == nil {
		return nil
	}
	// "sync stdout: The handle is invalid" is a known Windows issue.
	err := l.z.Sync()
	if err != nil && (errors.Is(err, os.ErrInvalid) || err.Error() == "sync stdout: The handle is invalid") {
		return nil
	}
	return err
}

func stderrSink() io.Writer { return os.Stderr }

type unknownFormatError struct{ format string }

func (e unknownFormatError) Error() string { return "logging: unknown format: " + e.format }
