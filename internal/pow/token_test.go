package pow

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encodeToken(t *testing.T, p TokenPayload) string {
	t.Helper()
	b, err := json.Marshal(p)
	require.NoError(t, err)
	return base64URL(string(b))
}

func base64URL(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := []byte(s)
	out := make([]byte, 0, ((len(b)+2)/3)*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		var cnt int
		for j := 0; j < 3 && i+j < len(b); j++ {
			n |= uint32(b[i+j]) << (16 - 8*j)
			cnt++
		}
		for j := 0; j < cnt+1; j++ {
			out = append(out, alphabet[(n>>(18-6*j))&0x3F])
		}
	}
	return string(out)
}

func TestDecodeToken_Valid(t *testing.T) {
	raw := encodeToken(t, TokenPayload{
		Version: 1, Mode: "generic", Algorithm: "sha256",
		Path: "/ubuntu.iso", Timestamp: 1735689600, ExpiresAt: 1735691400,
		Difficulty: 22, Counter: "000000000012abc", Salt: "2025-demo",
	})
	p, err := DecodeToken(raw)
	require.NoError(t, err)
	assert.Equal(t, "generic", p.Mode)
	assert.Equal(t, "/ubuntu.iso", p.Path)
	assert.Equal(t, int64(1735689600), p.Timestamp)
	assert.Equal(t, 22, p.Difficulty)
}

func TestDecodeToken_Empty(t *testing.T) {
	_, err := DecodeToken("")
	require.ErrorIs(t, err, ErrEmpty)
}

func TestDecodeToken_BadBase64(t *testing.T) {
	_, err := DecodeToken("not!valid!base64!!!")
	require.ErrorIs(t, err, ErrMalformed)
}

func TestDecodeToken_BadJSON(t *testing.T) {
	raw := base64URL("{not json")
	_, err := DecodeToken(raw)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestValidatePayload_Success(t *testing.T) {
	p := &TokenPayload{
		Version: 1, Mode: "generic", Algorithm: "sha256",
		Path: "/ubuntu.iso", Timestamp: 1, ExpiresAt: 2,
		Difficulty: 22, Counter: "abc", Salt: "",
	}
	err := ValidatePayload(p, &ValidatorOptions{AllowEmptySalt: true, AllowedModes: []string{"generic"}, MinDifficulty: 10, MaxDifficulty: 30})
	require.NoError(t, err)
}

func TestValidatePayload_BadVersion(t *testing.T) {
	p := &TokenPayload{Version: 2, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrUnsupportedVersion)
}

func TestValidatePayload_BadMode(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "weird", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrUnsupportedMode)
}

func TestValidatePayload_BadAlgorithm(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "md5", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestValidatePayload_PathNoSlash(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrPathInvalid)
}

func TestValidatePayload_PathTooLong(t *testing.T) {
	long := "/" + strings.Repeat("a", MaxPathLength)
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: long, Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrPathTooLong)
}

func TestValidatePayload_IPBoundRequiresIP(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "ip_bound", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, &ValidatorOptions{RequireIP: true, AllowedModes: []string{"ip_bound"}})
	require.ErrorIs(t, err, ErrIPMissing)
}

func TestValidatePayload_IPBoundBadIP(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "ip_bound", Algorithm: "sha256", IP: "not-an-ip", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrIPInvalid)
}

func TestValidatePayload_GenericForbiddenIP(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", IP: "1.2.3.4", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a"}
	err := ValidatePayload(p, nil)
	require.ErrorIs(t, err, ErrIPForbidden)
}

func TestValidatePayload_BadCounter(t *testing.T) {
	cases := []string{"", "with space", "with\nnewline", strings.Repeat("a", MaxCounterLength+1)}
	for _, c := range cases {
		p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: c}
		err := ValidatePayload(p, nil)
		require.ErrorIs(t, err, ErrCounterInvalid, "counter %q should be invalid", c)
	}
}

func TestValidatePayload_DifficultyOutOfRange(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 5, Counter: "a"}
	err := ValidatePayload(p, &ValidatorOptions{MinDifficulty: 10, MaxDifficulty: 30})
	require.ErrorIs(t, err, ErrDifficultyInvalid)
}

func TestValidatePayload_SaltNotAllowed(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a", Salt: "rogue"}
	err := ValidatePayload(p, &ValidatorOptions{AllowEmptySalt: true, AllowedSalts: []string{"2025"}})
	require.ErrorIs(t, err, ErrSaltInvalid)
}

func TestValidatePayload_BadTimestampOrExpiry(t *testing.T) {
	cases := []struct {
		name string
		p    TokenPayload
		want error
	}{
		{"ts zero", TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 0, ExpiresAt: 2, Difficulty: 1, Counter: "a"}, ErrTimestampInvalid},
		{"exp zero", TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 0, Difficulty: 1, Counter: "a"}, ErrExpiryInvalid},
		{"exp <= ts", TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 5, ExpiresAt: 5, Difficulty: 1, Counter: "a"}, ErrExpiryInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(&tc.p, nil)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestBuildCanonicalInput_IPBound(t *testing.T) {
	p := &TokenPayload{
		Version: 1, Mode: "ip_bound", Algorithm: "sha256",
		IP: "203.0.113.10", Path: "/ubuntu.iso",
		Timestamp: 1735689600, ExpiresAt: 1735776000, Difficulty: 22,
		Counter: "000000000012abc", Salt: "2025-demo",
	}
	got := BuildCanonicalInput(p)
	want := "mirrors-pow-v1\nmode=ip_bound\nip=203.0.113.10\npath=/ubuntu.iso\nts=1735689600\nexp=1735776000\ndifficulty=22\ncnt=000000000012abc\nsalt=2025-demo\n"
	assert.Equal(t, want, got)
}

func TestBuildCanonicalInput_Generic_HasEmptyIPLine(t *testing.T) {
	p := &TokenPayload{
		Version: 1, Mode: "generic", Algorithm: "sha256",
		Path: "/ubuntu.iso", Timestamp: 1735689600, ExpiresAt: 1735691400,
		Difficulty: 22, Counter: "000000000012abc", Salt: "2025-demo",
	}
	got := BuildCanonicalInput(p)
	assert.Contains(t, got, "mode=generic\nip=\npath=/ubuntu.iso")
	assert.True(t, strings.HasSuffix(got, "salt=2025-demo\n"))
}

func TestBuildCanonicalInput_StableAcrossCalls(t *testing.T) {
	p := &TokenPayload{Version: 1, Mode: "generic", Algorithm: "sha256", Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a", Salt: "s"}
	first := BuildCanonicalInput(p)
	second := BuildCanonicalInput(p)
	assert.Equal(t, first, second)
}

func TestComputeSign_EqualsSHA256OfCanonical(t *testing.T) {
	p := &TokenPayload{
		Version: 1, Mode: "generic", Algorithm: "sha256",
		Path: "/x", Timestamp: 1, ExpiresAt: 2, Difficulty: 1, Counter: "a", Salt: "s",
	}
	got := ComputeSign(p)
	canon := BuildCanonicalInput(p)
	sum := sha256.Sum256([]byte(canon))
	want := hex.EncodeToString(sum[:])
	assert.Equal(t, want, got)
}

func TestCompareSign_CaseInsensitive(t *testing.T) {
	assert.True(t, CompareSign("ABCDEF", "abcdef"))
	assert.True(t, CompareSign("abcdef", "ABCDEF"))
	assert.False(t, CompareSign("abc", "abcd"))
	assert.False(t, CompareSign("", "abc"))
	assert.False(t, CompareSign("abc", ""))
}

func TestHasLeadingZeroBits_Boundaries(t *testing.T) {
	// 0 bits always true
	assert.True(t, HasLeadingZeroBits([]byte{0xff}, 0))
	// 1 bit: high bit of first byte must be 0
	assert.True(t, HasLeadingZeroBits([]byte{0x7f}, 1))
	assert.False(t, HasLeadingZeroBits([]byte{0x80}, 1))
	// 7 bits
	assert.True(t, HasLeadingZeroBits([]byte{0x01}, 7))
	assert.False(t, HasLeadingZeroBits([]byte{0x02}, 7))
	// 8 bits: first byte must be 0
	assert.True(t, HasLeadingZeroBits([]byte{0x00, 0xff}, 8))
	assert.False(t, HasLeadingZeroBits([]byte{0x01, 0xff}, 8))
	// 9 bits: first byte 0 AND high bit of second byte 0
	assert.True(t, HasLeadingZeroBits([]byte{0x00, 0x7f}, 9))
	assert.False(t, HasLeadingZeroBits([]byte{0x00, 0x80}, 9))
	// 16 bits: first two bytes 0
	assert.True(t, HasLeadingZeroBits([]byte{0x00, 0x00, 0xff}, 16))
	assert.False(t, HasLeadingZeroBits([]byte{0x00, 0x01, 0xff}, 16))
	// 22 bits: first two bytes 0 AND high 6 bits of third byte 0
	assert.True(t, HasLeadingZeroBits([]byte{0x00, 0x00, 0x03, 0xff}, 22))
	assert.False(t, HasLeadingZeroBits([]byte{0x00, 0x00, 0x04, 0xff}, 22))
	// More than hash length
	assert.False(t, HasLeadingZeroBits([]byte{0x00}, 9))
}

func TestComputeSignID_StableAndDistinct(t *testing.T) {
	base := func() *TokenPayload {
		return &TokenPayload{
			Version: 1, Mode: "generic", Algorithm: "sha256",
			Path: "/ubuntu.iso", Timestamp: 1735689600, ExpiresAt: 1735691400,
			Difficulty: 22, Counter: "abc", Salt: "2025-demo",
		}
	}

	id1 := ComputeSignID(base(), "sign-x", "generic")
	id2 := ComputeSignID(base(), "sign-x", "generic")
	assert.Equal(t, id1, id2, "same payload must yield the same id")
	assert.Len(t, id1, 64)

	assert.NotEqual(t, id1, ComputeSignID(base(), "sign-y", "generic"),
		"a different sign must yield a different id")

	other := base()
	other.Path = "/debian.iso"
	assert.NotEqual(t, id1, ComputeSignID(other, "sign-x", "generic"),
		"a different path must yield a different id")

	later := base()
	later.Timestamp++
	assert.NotEqual(t, id1, ComputeSignID(later, "sign-x", "generic"),
		"a different timestamp must yield a different id")
}

// TestComputeSignID_IndependentOfEncoding is the regression guard for the
// max_uses bypass: one PoW solution has many wire encodings (trailing
// whitespace, base64 padding), and every one of them must map to the same
// usage record. Keying on the raw token instead let an attacker mint an
// unlimited number of distinct ids from a single computation.
func TestComputeSignID_IndependentOfEncoding(t *testing.T) {
	p := &TokenPayload{
		Version: 1, Mode: "generic", Algorithm: "sha256",
		Path: "/ubuntu.iso", Timestamp: 1735689600, ExpiresAt: 1735691400,
		Difficulty: 22, Counter: "abc", Salt: "2025-demo",
	}
	sign := ComputeSign(p)
	want := ComputeSignID(p, sign, "generic")

	raw, err := json.Marshal(p)
	require.NoError(t, err)

	encodings := map[string]string{
		"unpadded base64url": base64.RawURLEncoding.EncodeToString(raw),
		"padded base64url":   base64.URLEncoding.EncodeToString(raw),
		"trailing space":     base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), ' ')),
		"trailing newline":   base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), '\n')),
	}

	for name, token := range encodings {
		decoded, err := DecodeToken(token)
		require.NoError(t, err, name)
		assert.Equal(t, want, ComputeSignID(decoded, sign, "generic"),
			"%s decodes to the same payload and must share one usage record", name)
	}
}

// TestValidatePayload_RejectsCanonicalInjection covers fields that are
// interpolated into the canonical signing string. BuildCanonicalInput
// joins "key=value" pairs with newlines, so a value carrying a newline can
// append lines the signer never intended.
//
// Nothing upstream currently lets such a path through, but the validator
// should not depend on that: the check belongs next to the format it
// protects.
func TestValidatePayload_RejectsCanonicalInjection(t *testing.T) {
	opts := &ValidatorOptions{
		AllowedModes:   []string{"generic"},
		AllowedSalts:   []string{"s", "s\nexp=999"},
		AllowEmptySalt: true,
		MinDifficulty:  1,
		MaxDifficulty:  64,
	}
	base := func() *TokenPayload {
		return &TokenPayload{
			Version: 1, Mode: "generic", Algorithm: "sha256",
			Path: "/ok", Timestamp: 1, ExpiresAt: 2,
			Difficulty: 22, Counter: "abc", Salt: "s",
		}
	}
	require.NoError(t, ValidatePayload(base(), opts), "baseline must be valid")

	for _, tc := range []struct {
		name string
		mut  func(*TokenPayload)
		want error
	}{
		{"newline in path", func(p *TokenPayload) { p.Path = "/a\nts=999" }, ErrPathInvalid},
		{"carriage return in path", func(p *TokenPayload) { p.Path = "/a\rts=999" }, ErrPathInvalid},
		{"NUL in path", func(p *TokenPayload) { p.Path = "/a\x00b" }, ErrPathInvalid},
		{"newline in salt", func(p *TokenPayload) { p.Salt = "s\nexp=999" }, ErrSaltInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.mut(p)
			assert.ErrorIs(t, ValidatePayload(p, opts), tc.want)
		})
	}
}

// Salt matching is case-sensitive: salt goes verbatim into the canonical
// input, so differing case is a different sign. The removed SaltAllowed
// helper used EqualFold and contradicted this.
func TestValidatePayload_SaltMatching(t *testing.T) {
	base := func(salt string) *TokenPayload {
		return &TokenPayload{
			Version: 1, Mode: "generic", Algorithm: "sha256",
			Path: "/a.iso", Timestamp: 1, ExpiresAt: 2,
			Difficulty: 22, Counter: "c", Salt: salt,
		}
	}
	opts := &ValidatorOptions{
		AllowedModes:  []string{"generic"},
		AllowedSalts:  []string{"2025-demo"},
		MinDifficulty: 1, MaxDifficulty: 64,
	}

	assert.NoError(t, ValidatePayload(base("2025-demo"), opts))
	assert.ErrorIs(t, ValidatePayload(base("2025-DEMO"), opts), ErrSaltInvalid)
	assert.ErrorIs(t, ValidatePayload(base("rogue"), opts), ErrSaltInvalid)
	assert.ErrorIs(t, ValidatePayload(base(""), opts), ErrSaltInvalid)

	allowEmpty := *opts
	allowEmpty.AllowEmptySalt = true
	assert.NoError(t, ValidatePayload(base(""), &allowEmpty))
}

func TestMinimumSignForDifficulty(t *testing.T) {
	assert.Equal(t, "", MinimumSignForDifficulty(0))
	// 4 bits = one hex 0
	assert.Equal(t, "0", MinimumSignForDifficulty(4))
	// 22 bits = 5 nibbles of 0 + one nibble <= 3 (binary 0011)
	got := MinimumSignForDifficulty(22)
	assert.Equal(t, "000003", got)
	// 8 bits = two hex 0s
	assert.Equal(t, "00", MinimumSignForDifficulty(8))
}

// Round-trip helper: build a token, encode it, decode, verify.
func ExampleComputeSign() {
	p := &TokenPayload{
		Version: 1, Mode: "generic", Algorithm: "sha256",
		Path: "/ubuntu.iso", Timestamp: 1735689600, ExpiresAt: 1735691400,
		Difficulty: 22, Counter: "000000000012abc", Salt: "2025-demo",
	}
	sign := ComputeSign(p)
	fmt.Println(len(sign))
	// Output: 64
}

// TestValidatePayload_AlgorithmFromOptions: the expected hash must come from
// options, not a hardcoded constant.
func TestValidatePayload_AlgorithmFromOptions(t *testing.T) {
	mk := func(alg string) *TokenPayload {
		return &TokenPayload{
			Version: 1, Mode: "generic", Algorithm: alg,
			Path: "/a.iso", Timestamp: 1, ExpiresAt: 2,
			Difficulty: 22, Counter: "c", Salt: "s",
		}
	}
	opts := &ValidatorOptions{
		AllowedModes:  []string{"generic"},
		AllowedSalts:  []string{"s"},
		MinDifficulty: 1, MaxDifficulty: 64,
	}

	// Empty Algorithm falls back to the default, so a zero-value options
	// struct still rejects an unknown hash rather than accepting anything.
	assert.NoError(t, ValidatePayload(mk("sha256"), opts))
	assert.ErrorIs(t, ValidatePayload(mk("sha512"), opts), ErrUnsupportedAlgorithm)
	assert.ErrorIs(t, ValidatePayload(mk(""), opts), ErrUnsupportedAlgorithm)

	// An explicit Algorithm is honoured.
	withAlg := *opts
	withAlg.Algorithm = "sha256"
	assert.NoError(t, ValidatePayload(mk("SHA256"), &withAlg), "case-insensitive")
	assert.ErrorIs(t, ValidatePayload(mk("md5"), &withAlg), ErrUnsupportedAlgorithm)
}
