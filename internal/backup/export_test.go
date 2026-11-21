package backup

import "testing"

// SetLimitsForTest shrinks the expanded limit so over-limit refusals are tested without
// allocating 256 MiB.
func SetLimitsForTest(t testing.TB, limit int64) {
	ol := expandLimit
	expandLimit = limit
	t.Cleanup(func() { expandLimit = ol })
}
