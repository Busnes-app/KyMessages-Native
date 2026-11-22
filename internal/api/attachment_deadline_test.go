package api

import (
	"testing"
	"time"

	"github.com/Busnes-app/ky_server_base/internal/config"
)

// The upload deadline covers the largest allowed file on a 1 Mbit/s uplink.
func TestAttachmentUploadDeadlineCoversASlowUplink(t *testing.T) {
	const uplink = 1_000_000 / 8 // bytes per second
	for _, maxBytes := range []int64{config.DefaultMaxUploadBytes, config.MaxAllowedUploadBytes} {
		need := time.Duration(maxBytes/uplink) * time.Second
		if got := attachmentUploadDeadline(maxBytes); got < need {
			t.Errorf("deadline for %d bytes = %v, want at least %v", maxBytes, got, need)
		}
	}
}
