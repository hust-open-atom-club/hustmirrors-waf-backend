package pow

// Salt is validated in ValidatePayload with an exact ==, deliberately
// case-sensitive: salt goes verbatim into the canonical signing input, so
// "2025-demo" and "2025-DEMO" produce different signs.
//
// A SaltAllowed helper here used EqualFold and had no callers, so the two
// rules contradicted each other. Removed rather than reconciled.
