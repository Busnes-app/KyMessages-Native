//go:build js && wasm

// The identity adapter adds KyMessages' wire API to ky-primitives/cmd/pqwasm at build time.
// Cryptographic primitives and the runtime entry point come from the pinned module; product
// encodings stay in e2eeid, shared with the server. scripts/build-pqwasm.sh stages the sources.
package main

import (
	"os"
	"syscall/js"

	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
)

func init() {
	// The call is handed to the loader rather than set as a global: a start the loader gave up
	// on must not replace a newer one when it finishes late.
	call := js.FuncOf(func(_ js.Value, argv []js.Value) (result any) {
		// A panic in a call must answer an error, not kill the Go runtime every later call needs.
		defer func() {
			if r := recover(); r != nil {
				result = map[string]any{"error": "kyPQCCall: internal error"}
			}
		}()
		if len(argv) == 0 || argv[0].Type() != js.TypeString {
			return map[string]any{"error": "kyPQCCall: name the call"}
		}
		args := make([]string, len(argv)-1)
		for i, a := range argv[1:] {
			if a.Type() != js.TypeString {
				return map[string]any{"error": "kyPQCCall: arguments are strings"}
			}
			args[i] = a.String()
		}
		out, err := e2eeid.Call(argv[0].String(), args)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		if m, ok := out.(map[string]string); ok {
			o := make(map[string]any, len(m))
			for k, v := range m {
				o[k] = v
			}
			out = o
		}
		return map[string]any{"ok": out}
	})
	// The generation travels with the call: a start the loader gave up on that reaches the newest
	// start's kyPQCReady names its own, older generation and is ignored.
	gen := ""
	if len(os.Args) > 1 {
		gen = os.Args[1]
	}
	js.Global().Get("kyPQCReady").Invoke(gen, call)
}
