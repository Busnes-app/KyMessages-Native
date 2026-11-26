package api

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// No E3 request body has a field that could carry a private key, a recovery key or a Megolm
// session key (spec §9). Wrapped and sealed fields hold ciphertext only.
func TestE2EEIdentityBodiesCarryNoSecrets(t *testing.T) {
	secret := regexp.MustCompile(`private|secret|seed|recovery_key|session_key|plaintext`)
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, path string) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice:
			walk(typ.Elem(), path)
		case reflect.Struct:
			for i := range typ.NumField() {
				f := typ.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if tag == "" || tag == "-" {
					t.Errorf("%s.%s has no JSON name", path, f.Name)
				}
				if secret.MatchString(tag) {
					t.Errorf("%s.%s accepts %q", path, f.Name, tag)
				}
				walk(f.Type, path+"."+tag)
			}
		}
	}
	for _, v := range []any{e2eeMasterPut{}, e2eePinsPut{}, e2eeDeviceSignature{}, e2eeBackupPut{}, e2eePairingStart{}, e2eePairingJoin{}, e2eePairingSeal{}, e2eeDeviceListPut{}, e2eeDeviceListReserve{}} {
		walk(reflect.TypeOf(v), reflect.TypeOf(v).Name())
	}
}
