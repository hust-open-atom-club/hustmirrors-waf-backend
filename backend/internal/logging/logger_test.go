package logging

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestHashIP_StableAndSalted(t *testing.T) {
	a := HashIP("203.0.113.10", "salt1")
	b := HashIP("203.0.113.10", "salt1")
	assert.Equal(t, a, b, "same ip+salt should hash identically")

	c := HashIP("203.0.113.10", "salt2")
	assert.NotEqual(t, a, c, "different salt should differ")

	d := HashIP("203.0.113.11", "salt1")
	assert.NotEqual(t, a, d, "different ip should differ")
}

func TestHashIP_InvalidReturnedAsIs(t *testing.T) {
	got := HashIP("not-an-ip", "salt")
	assert.Equal(t, "not-an-ip", got)
}

func TestHashIP_Empty(t *testing.T) {
	assert.Empty(t, HashIP("", "salt"))
}

func TestCtxFields_Propagate(t *testing.T) {
	var buf bytes.Buffer
	ec := zap.NewProductionEncoderConfig()
	ec.EncodeTime = func(_ time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString("0")
	}
	enc := zapcore.NewJSONEncoder(ec)
	core := zapcore.NewCore(enc, zapcore.AddSync(&buf), zapcore.InfoLevel)
	z := zap.New(core)
	l := NewFromZap(z)

	ctx := WithFields(context.Background(), String("request_id", "rid-123"))
	l.Info(ctx, "hello", String("path", "/ubuntu.iso"))

	out := buf.String()
	require.Contains(t, out, `"msg":"hello"`)
	require.Contains(t, out, `"request_id":"rid-123"`)
	require.Contains(t, out, `"path":"/ubuntu.iso"`)
}

func TestFromContext_NoLogger(t *testing.T) {
	l := FromContext(context.Background())
	assert.NotPanics(t, func() {
		l.Info(context.Background(), "ok")
	})
}

func TestNew_UnknownLevel(t *testing.T) {
	_, err := New("trace", "json")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "level"))
}

func TestNew_UnknownFormat(t *testing.T) {
	_, err := New("info", "xml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xml")
}
