package vault

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestOpenRequestMetaForms reads both meta forms and refuses everything else,
// as the web app does (spec/vectors/README.md, decision 9).
func TestOpenRequestMetaForms(t *testing.T) {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	id := strings.Repeat("ab", 16)
	idBytes, _ := hex.DecodeString(id)
	open := func(rest string) ([]string, error) {
		pt := `{"name":"stripe","description":"d","env":"","context":""` + rest + `}`
		ct := must(sealEnvelope(keys.RK, make([]byte, NonceSize), []byte(pt), requestMetaAAD(vecAccountID, idBytes)))
		m, err := OpenRequestMeta(keys.RK, vecAccountID, id, ct)
		return m.Fields, err
	}
	for rest, want := range map[string]string{`,"fields":["client_id","secret"]`: "client_id,secret", `,"field":"token"`: "token", `,"field":""`: ""} {
		if got, err := open(rest); err != nil || strings.Join(got, ",") != want {
			t.Fatalf("%s: %v %v", rest, got, err)
		}
	}
	for _, rest := range []string{``, `,"fields":[]`, `,"fields":["a","A"]`, `,"fields":["a"],"field":"a"`, `,"fields":null,"field":"x"`, `,"field":null,"fields":["a"]`, `,"field":null`, `,"fields":null`} {
		if got, err := open(rest); err == nil {
			t.Fatalf("%s accepted as %v", rest, got)
		}
	}
}
