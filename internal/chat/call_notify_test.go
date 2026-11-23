package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func largeCallEvent() Event {
	return Event{Type: EventCallSignal, RoomID: "room", UserID: "recipient", Data: MustMarshalData(CallSignalPayload{RoomID: "room", FromPeerID: "from", ToPeerID: "to", Kind: "offer", Data: MustMarshalData(map[string]string{"sdp": strings.Repeat("SDP", 16000)})})}
}

func TestCallNotifyReassemblesFullTargetedControl(t *testing.T) {
	for _, typ := range []string{EventCallSignal, EventCallMigrate, EventCallState} {
		t.Run(typ, func(t *testing.T) {
			ev := largeCallEvent()
			ev.Type = typ
			parts, err := encodeBusNotifications(ev)
			if err != nil || len(parts) < 2 {
				t.Fatalf("parts: %d %v", len(parts), err)
			}
			var d callNotifyDecoder
			now := time.Unix(100, 0)
			for i := len(parts) - 1; i >= 0; i-- {
				if len(parts[i]) > MaxNotifyBytes {
					t.Fatalf("part over notification limit: %d", len(parts[i]))
				}
				got, err := d.decode(parts[i], now)
				if err != nil {
					t.Fatal(err)
				}
				if i != 0 {
					if got != nil {
						t.Fatal("incomplete event escaped")
					}
					if got, err := d.decode(parts[i], now); got != nil || err != nil {
						t.Fatalf("duplicate part: %+v %v", got, err)
					}
				} else if got == nil || got.UserID != ev.UserID || got.RoomID != ev.RoomID || got.Type != typ || !bytes.Equal(got.Data, ev.Data) {
					t.Fatalf("targeted payload changed: %+v %v", got, err)
				}
			}
			if len(d.pending) != 0 {
				t.Fatal("completed event retained")
			}
		})
	}
}

func TestCallNotifyBoundsCorruptionAndMissingParts(t *testing.T) {
	ev := largeCallEvent()
	parts, err := encodeBusNotifications(ev)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	var d callNotifyDecoder
	if got, err := d.decode(parts[0], now); got != nil || err != nil {
		t.Fatalf("first part: %+v %v", got, err)
	}
	if got, err := d.decode(parts[1], now.Add(callNotifyTTL)); got != nil || err != nil {
		t.Fatalf("expired first part: %+v %v", got, err)
	}
	if len(d.pending) != 1 {
		t.Fatalf("expired group retained: %d", len(d.pending))
	}
	var envelope callNotifyEnvelope
	if err := json.Unmarshal([]byte(parts[0]), &envelope); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPendingCallNotifies+10; i++ {
		envelope.Part.ID = fmt.Sprintf("%036d", i)
		raw, _ := json.Marshal(envelope)
		if got, err := d.decode(string(raw), now); got != nil || err != nil {
			t.Fatalf("bounded incomplete event: %+v %v", got, err)
		}
	}
	if len(d.pending) != maxPendingCallNotifies {
		t.Fatalf("pending groups unbounded: %d", len(d.pending))
	}
	var corrupt callNotifyDecoder
	for i, p := range parts {
		if i == len(parts)-1 {
			var e callNotifyEnvelope
			_ = json.Unmarshal([]byte(p), &e)
			e.Part.Data[0] ^= 1
			raw, _ := json.Marshal(e)
			p = string(raw)
		}
		got, err := corrupt.decode(p, now)
		if got != nil {
			t.Fatal("corrupt event reached client")
		}
		if i == len(parts)-1 && err == nil {
			t.Fatal("corrupt checksum accepted")
		}
	}
	if len(corrupt.pending) != 0 {
		t.Fatal("corrupt event retained")
	}
	envelope.Part.Total = maxCallNotifyBytes/callNotifyPartBytes + 1
	raw, _ := json.Marshal(envelope)
	if got, err := d.decode(string(raw), now); got != nil || err == nil {
		t.Fatal("oversize part count accepted")
	}
	ev.Data = MustMarshalData(strings.Repeat("x", maxCallNotifyBytes))
	if _, err := encodeBusNotifications(ev); err == nil {
		t.Fatal("oversize call event accepted")
	}
}

type notifyCapture struct{ payloads []string }

func (n *notifyCapture) Notify(_ context.Context, _, payload string) error {
	n.payloads = append(n.payloads, payload)
	return nil
}

func TestSingleModeNotifyKeepsExistingRefetchBytes(t *testing.T) {
	ev := largeCallEvent()
	want, err := encodeNotifyPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	n := new(notifyCapture)
	bus := NewPostgresBus("", n)
	if err := bus.PublishUser(context.Background(), ev.UserID, ev); err != nil {
		t.Fatal(err)
	}
	if len(n.payloads) != 1 || n.payloads[0] != want {
		t.Fatal("single-mode notification bytes changed")
	}
	n.payloads = nil
	bus.EnableCallFragments()
	if err := bus.PublishUser(context.Background(), ev.UserID, ev); err != nil {
		t.Fatal(err)
	}
	if len(n.payloads) < 2 {
		t.Fatal("multi-mode call still replaced with refetch")
	}
	// Ordinary message notifications retain the existing small/refetch wire contract too.
	ev.Type = EventMessageNew
	want, err = encodeNotifyPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	n.payloads = nil
	if err := bus.PublishUser(context.Background(), ev.UserID, ev); err != nil {
		t.Fatal(err)
	}
	if len(n.payloads) != 1 || n.payloads[0] != want {
		t.Fatal("message refetch behavior changed")
	}
}

// Keep the same room from another event from filling holes in a missing fragmented signal.
func TestCallNotifyDoesNotMixInterleavedEvents(t *testing.T) {
	ev := largeCallEvent()
	a, err := encodeBusNotifications(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev.UserID = "other"
	b, err := encodeBusNotifications(ev)
	if err != nil {
		t.Fatal(err)
	}
	var d callNotifyDecoder
	now := time.Unix(100, 0)
	for i := range a {
		got, err := d.decode(a[i], now)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil && got.UserID != "recipient" {
			t.Fatal("first event crossed recipient")
		}
		if i == 1 {
			continue
		}
		got, err = d.decode(b[i], now)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatal("incomplete second signal escaped")
		}
	}
	var e callNotifyEnvelope
	_ = json.Unmarshal([]byte(b[0]), &e)
	e.Part.ID = uuid.NewString()
	e.Part.Total = 1
	raw, _ := json.Marshal(e)
	if _, err := d.decode(string(raw), now); err == nil {
		t.Fatal("invalid fragmented event accepted")
	}
}
