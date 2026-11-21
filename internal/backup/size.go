package backup

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky_server_base/internal/config"
)

// LastSizeSetting holds the last measured expanded size of the server capsule, in bytes.
const LastSizeSetting = "backup_last_expanded_bytes"

// expandLimit is the expanded-archive budget enforced before sealing. Tests may shrink it.
var expandLimit int64 = capsule.MaxExpandedBytes

// SetExpandLimitForTest overrides the expanded-size cap for tests and returns a restore func.
func SetExpandLimitForTest(limit int64) func() {
	prev := expandLimit
	expandLimit = limit
	return func() { expandLimit = prev }
}

// SizeError reports that a capsule payload exceeds the maximum expanded size.
// It unwraps to capsule.ErrCapsuleTooLarge so callers can handle both generically and with detail.
type SizeError struct {
	Bytes  int64
	Limit  int64
	Member string
}

func (e *SizeError) Error() string {
	mib := func(n int64) float64 { return float64(n) / (1 << 20) }
	if e.Member != "" {
		return fmt.Sprintf("backup: capsule payload is %.1f MiB, over the %.1f MiB limit (largest: %s)", mib(e.Bytes), mib(e.Limit), e.Member)
	}
	return fmt.Sprintf("backup: capsule payload is %.1f MiB, over the %.1f MiB limit", mib(e.Bytes), mib(e.Limit))
}

func (e *SizeError) Unwrap() error { return capsule.ErrCapsuleTooLarge }

func memberBytes(path string, size int64) int64 {
	return int64(len(path)) + size
}

// Measure returns the expanded byte total counted against the capsule size limit.
func Measure(files []recoveryclient.File) int64 {
	var total int64
	for _, f := range files {
		total += memberBytes(f.Path, int64(len(f.Data)))
	}
	return total
}

type budget struct {
	total        int64
	largestPath  string
	largestBytes int64
}

func (b *budget) add(path string, size int64) {
	n := memberBytes(path, size)
	b.total += n
	if n > b.largestBytes {
		b.largestBytes = n
		b.largestPath = path
	}
}

func (b *budget) err() error {
	if b.total > expandLimit {
		return &SizeError{Bytes: b.total, Limit: expandLimit, Member: b.largestPath}
	}
	return nil
}

// CollectForRun is Collect for a backup run: it records the measured size, over the limit or
// not, for the status screen. A failed write only costs the screen its number.
func CollectForRun(ctx context.Context, cfg *config.Config, s recoveryclient.Settings, appVersion string) (recoveryclient.Payload, error) {
	p, err := Collect(ctx, cfg, appVersion)
	var se *SizeError
	switch {
	case err == nil:
		_ = s.Set(LastSizeSetting, strconv.FormatInt(Measure(p.Files), 10))
	case errors.As(err, &se):
		_ = s.Set(LastSizeSetting, strconv.FormatInt(se.Bytes, 10))
	}
	return p, err
}

// SizeStatus is the last measured size against the capsule's expanded limit.
type SizeStatus struct {
	Bytes   int64 `json:"bytes"`
	Limit   int64 `json:"limit"`
	Percent int   `json:"percent"`
	Warning bool  `json:"warning"` // at or past 75% of Limit
}

// LastSize reads LastSizeSetting; ok is false before the first run.
func LastSize(s recoveryclient.Settings) (SizeStatus, bool, error) {
	v, err := s.Get(LastSizeSetting)
	if errors.Is(err, recoveryclient.ErrNotFound) {
		return SizeStatus{}, false, nil
	}
	if err != nil {
		return SizeStatus{}, false, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return SizeStatus{}, false, fmt.Errorf("backup: %s is %q", LastSizeSetting, v)
	}
	limit := capsule.MaxExpandedBytes
	return SizeStatus{Bytes: n, Limit: limit, Percent: int(n * 100 / limit), Warning: n*4 >= limit*3}, true, nil
}
