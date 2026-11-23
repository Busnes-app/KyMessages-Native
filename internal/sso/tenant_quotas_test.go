package sso

import (
	"encoding/json"
	"testing"
)

func TestTenantQuotaBoundary(t *testing.T) {
	for _, body := range []string{"", "null", "[]", `{"unknown":1}`, `{"max_upload_bytes":null}`, `{"max_upload_bytes":0}`, `{"max_upload_bytes":1023}`, `{"max_upload_bytes":104857601}`, `{"max_upload_bytes":"2048"}`, `{"max_upload_bytes":1.5}`, `{"max_pending_user_bytes":-1}`, `{} {}`} {
		if _, err := parseTenantQuotas(json.RawMessage(body)); err == nil {
			t.Errorf("accepted %q", body)
		}
	}
	q, err := parseTenantQuotas(json.RawMessage(`{"max_upload_bytes":2048,"max_pending_user_bytes":4096}`))
	if err != nil || q.MaxUploadBytes != 2048 || q.MaxPendingUserBytes != 4096 {
		t.Fatalf("valid quotas: %+v %v", q, err)
	}
	q, err = parseTenantQuotas(json.RawMessage(`{}`))
	if err != nil || q.MaxUploadBytes != 0 || q.MaxPendingUserBytes != 0 {
		t.Fatalf("install defaults: %+v %v", q, err)
	}
}
