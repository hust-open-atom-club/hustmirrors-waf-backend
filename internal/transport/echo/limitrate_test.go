package echo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLimitRateBytes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "0"},
		{"0", "0"},
		{"512k", "524288"},
		{"128k", "131072"},
		{"1m", "1048576"},
		{"2m", "2097152"},
		{"1g", "1073741824"},
		{"1024", "1024"},
		{"512K", "524288"},
		{" 512k ", "524288"},
		{"abc", "0"},
		{"512x", "0"},
		{"-5k", "0"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, limitRateBytes(tc.in), "input %q", tc.in)
	}
}
