//go:build js && wasm

// Command pqc-wasm is the browser's post-quantum code: internal/e2eeid (and through it
// internal/pqc/xwing and internal/pqc/hybridsig) compiled to js/wasm, the same Go the server
// runs (PQC Stack Plan Q3). It defines globalThis.kyPQCCall(name, ...args), which answers
// {ok: result} or {error: message}, also for a call that panics. build.sh writes the committed
// web/src/pqc/pqc.wasm.
package main

import (
	"syscall/js"

	"github.com/Busnes-app/ky_server_base/internal/e2eeid"
)

func main() {
	js.Global().Set("kyPQCCall", js.FuncOf(func(_ js.Value, argv []js.Value) (result any) {
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
	}))
	js.Global().Get("kyPQCReady").Invoke()
	select {}
}
