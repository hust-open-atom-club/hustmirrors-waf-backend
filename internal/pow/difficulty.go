package pow

// HasLeadingZeroBits reports whether the first n bits of hash are zero.
//
// Hash is interpreted big-endian, MSB-first within each byte — same
// convention as Bitcoin's PoW.
//
// Edge cases:
//   - n == 0 always true (no difficulty requirement).
//   - n > len(hash)*8 returns false.
//   - n == 8 means the first byte must be 0.
//   - n == 9 means first byte 0 AND high bit of second byte 0.
func HasLeadingZeroBits(hash []byte, n int) bool {
	if n <= 0 {
		return true
	}
	if n > len(hash)*8 {
		return false
	}
	fullBytes := n / 8
	remBits := n % 8
	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if remBits > 0 {
		mask := byte(0xFF << (8 - remBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}
	return true
}

// HasLeadingZeroBits32 is the [32]byte flavour, used after sha256.Sum256
// without an extra slice header allocation.
func HasLeadingZeroBits32(hash [32]byte, n int) bool {
	return HasLeadingZeroBits(hash[:], n)
}

// MinimumSignForDifficulty returns the minimum acceptable hex prefix for
// the given difficulty. Mainly used by tests.
func MinimumSignForDifficulty(d int) string {
	if d <= 0 {
		return ""
	}
	fullHex := d / 4
	remBits := d % 4
	out := make([]byte, 0, fullHex+1)
	for i := 0; i < fullHex; i++ {
		out = append(out, '0')
	}
	if remBits > 0 {
		// Highest allowed nibble: 2^remBits - 1.
		max := byte(1<<remBits) - 1
		if max < 10 {
			out = append(out, '0'+max)
		} else {
			out = append(out, 'a'+max-10)
		}
	}
	return string(out)
}
