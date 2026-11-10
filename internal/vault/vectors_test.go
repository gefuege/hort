package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestVectors generates spec/vectors from production code with -update and
// otherwise requires the committed files to match byte for byte:
//
//	go test ./internal/vault/ -run TestVectors -update
var updateVectors = flag.Bool("update", false, "rewrite spec/vectors from production code")

const vectorDir = "../../spec/vectors"

func TestVectors(t *testing.T) {
	files := []struct {
		name  string
		build func(*testing.T) any
	}{
		{"canon.json", canonVectors},
		{"keys.json", keyVectors},
		{"kek.json", kekVectors},
		{"slot.json", slotVectors},
		{"passkey-slot.json", passkeySlotVectors},
		{"envelope.json", envelopeVectors},
		{"request.json", requestVectors},
		{"secret-key.json", secretKeyVectors},
		{"reduction.json", reductionVectors},
		{"share.json", shareVectors},
		{"fold.json", foldVectors},
	}
	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(f.build(t)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(vectorDir, f.name)
			if *updateVectors {
				if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (generate with -update)", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				got := strings.Split(buf.String(), "\n")
				exp := strings.Split(string(want), "\n")
				for i := 0; i < len(got) || i < len(exp); i++ {
					var g, e string
					if i < len(got) {
						g = got[i]
					}
					if i < len(exp) {
						e = exp[i]
					}
					if g != e {
						t.Fatalf("%s differs from production code at line %d:\n file: %s\n code: %s", f.name, i+1, e, g)
					}
				}
			}
		})
	}
}

// hexBytes marshals as lowercase hex.
type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

// fixed derives a reproducible input from a label; the files carry the bytes.
func fixed(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256(fmt.Appendf(nil, "hort/vectors/%s/%d", label, i))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// must panics, which fails the test with a stack trace.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

var (
	vecAccountID = fixed("account-id", AccountIDSize)
	vecVK        = fixed("vk", KeySize)
	vecSecretKey = fixed("secret-key", SecretKeySize)
	vecSlotSalt  = fixed("slot-salt", SaltSize)
	vecDeviceID  = fixed("device-id", 16)
	vecDeviceKey = ed25519.NewKeyFromSeed(fixed("device-seed", ed25519.SeedSize))
	testArgon    = ArgonParams{Time: 1, Memory: 256, Threads: 1}
)

type vectorFile struct {
	Description string `json:"description"`
	Vectors     any    `json:"vectors"`
}

func canonVectors(t *testing.T) any {
	type vec struct {
		Name   string     `json:"name"`
		Tag    string     `json:"tag"`
		Fields []hexBytes `json:"fields_hex"`
		Output hexBytes   `json:"output_hex"`
	}
	mk := func(name, tag string, fields ...[]byte) vec {
		hf := []hexBytes{}
		for _, f := range fields {
			hf = append(hf, f)
		}
		return vec{name, tag, hf, canon(tag, fields...)}
	}
	return vectorFile{
		Description: "canon(tag, f1..fn) = tag || u32be(len f1) || f1 || ... (contract §2.1). hort/v4/test is a test-only tag.",
		Vectors: []vec{
			mk("tag only", "hort/v4/test\n"),
			mk("one empty field", "hort/v4/test\n", []byte{}),
			mk("several fields including an empty one", "hort/v4/test\n", []byte("passphrase"), []byte{}, be64(1), []byte{0xff}),
			mk("passphrase slot_params", "hort/v4/argon\n", vecSlotSalt, be32(3), be32(65536), []byte{4}),
		},
	}
}

func keyVectors(t *testing.T) any {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	type vec struct {
		VK        hexBytes `json:"vk_hex"`
		AccountID hexBytes `json:"account_id_hex"`
		FK        hexBytes `json:"fk_hex"`
		RK        hexBytes `json:"rk_hex"`
		AKSeed    hexBytes `json:"aks_hex"`
		AKPublic  hexBytes `json:"ak_public_hex"`
	}
	return vectorFile{
		Description: "HKDF-SHA256(ikm=VK, salt=account_id, info) for FK (hort/v4/file), RK (hort/v4/revision), AKs (hort/v4/account-auth); AK = Ed25519 key from seed AKs (contract §2.1).",
		Vectors:     []vec{{vecVK, vecAccountID, keys.FK, keys.RK, keys.AK.Seed(), hexBytes(keys.AK.Public().(ed25519.PublicKey))}},
	}
}

type argonJSON struct {
	T uint32 `json:"t"`
	M uint32 `json:"m_kib"`
	P uint8  `json:"p"`
}

func argonOf(p ArgonParams) argonJSON { return argonJSON{p.Time, p.Memory, p.Threads} }

func kekVectors(t *testing.T) any {
	type passVec struct {
		Name          string    `json:"name"`
		TestParams    bool      `json:"test_params_only"`
		Passphrase    hexBytes  `json:"passphrase_utf8_hex"`
		PassphraseNFC hexBytes  `json:"passphrase_nfc_hex"`
		SecretKey     hexBytes  `json:"secret_key_hex"`
		AccountID     hexBytes  `json:"account_id_hex"`
		SlotSalt      hexBytes  `json:"slot_salt_hex"`
		Argon         argonJSON `json:"argon"`
		A             hexBytes  `json:"argon_output_hex"`
		S             hexBytes  `json:"secret_key_half_hex"`
		KEK           hexBytes  `json:"kek_hex"`
	}
	type passkeyVec struct {
		AccountID hexBytes `json:"account_id_hex"`
		EvalSalt  hexBytes `json:"prf_eval_salt_hex"`
		PRF       hexBytes `json:"prf_output_hex"`
		KEK       hexBytes `json:"kek_hex"`
	}
	nfc := "Grüße aus Hannover"
	nfd := "Gru\u0308ße aus Hannover"
	if nfc == nfd {
		t.Fatal("NFD fixture collapsed")
	}
	mk := func(name, pass string, p ArgonParams, test bool) passVec {
		kek := must(PassphraseKEK(pass, vecSecretKey, vecAccountID, vecSlotSalt, p))
		return passVec{name, test, []byte(pass), []byte(nfc), vecSecretKey, vecAccountID, vecSlotSalt, argonOf(p),
			passphraseArgon(pass, vecSlotSalt, p), must(secretKeyHalf(vecSecretKey, vecAccountID)), kek}
	}
	pass := []passVec{
		mk("production parameters", nfc, DefaultArgonParams(), false),
		mk("test parameters, NFC input", nfc, testArgon, true),
		mk("test parameters, NFD input normalizes to the same KEK", nfd, testArgon, true),
	}
	if !bytes.Equal(pass[1].KEK, pass[2].KEK) {
		t.Fatal("NFC and NFD passphrase derive different KEKs")
	}
	prf := fixed("prf-output", PRFSize)
	return vectorFile{
		Description: "Passphrase slot KEK by 2SKD and passkey slot KEK from PRF (contract §2.2). A = Argon2id(NFC(passphrase), slot_salt, t, m, p, 32); S = HKDF(secret_key, account_id, hort/v4/secret-key); KEK = HKDF(A XOR S, slot_salt, hort/v4/kek). Passkey: eval salt = SHA-256(\"hort/v4/prf\\n\" || account_id); KEK = HKDF(PRF, account_id, hort/v4/kek-passkey).",
		Vectors: map[string]any{
			"passphrase": pass,
			"passkey":    []passkeyVec{{vecAccountID, PRFEvalSalt(vecAccountID), prf, must(PasskeyKEK(prf, vecAccountID))}},
		},
	}
}

func slotVectors(t *testing.T) any {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	params := DefaultArgonParams()
	kek := must(PassphraseKEK("Grüße aus Hannover", vecSecretKey, vecAccountID, vecSlotSalt, params))
	nonce := fixed("nonce/slot", NonceSize)
	const version = 7
	slotParams := ArgonSlotParams(vecSlotSalt, params)
	wrapped := must(wrapVK(kek, vecVK, vecAccountID, PassphraseSlotID, version, slotParams, nonce))
	if vk := must(UnwrapVK(kek, nonce, wrapped, vecAccountID, PassphraseSlotID, version, slotParams)); !bytes.Equal(vk, vecVK) {
		t.Fatal("slot does not round-trip")
	}
	if _, err := UnwrapVK(kek, nonce, wrapped, vecAccountID, PassphraseSlotID, version+1, slotParams); err == nil {
		t.Fatal("slot opened under another slot_version")
	}
	slotBytes := SlotBytes(slotParams, nonce, wrapped)
	msg := SlotSigMessage(vecAccountID, PassphraseSlotID, version, slotBytes)
	sig := ed25519.Sign(keys.AK, msg)
	if !ed25519.Verify(keys.AK.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("ak_sig does not verify")
	}
	type vec struct {
		AccountID   hexBytes  `json:"account_id_hex"`
		VK          hexBytes  `json:"vk_hex"`
		KEK         hexBytes  `json:"kek_hex"`
		SlotID      string    `json:"slot_id"`
		SlotVersion uint64    `json:"slot_version"`
		SlotSalt    hexBytes  `json:"slot_salt_hex"`
		Argon       argonJSON `json:"argon"`
		SlotParams  hexBytes  `json:"slot_params_hex"`
		AAD         hexBytes  `json:"aad_hex"`
		Nonce       hexBytes  `json:"wrap_nonce_hex"`
		Wrapped     hexBytes  `json:"wrapped_vk_hex"`
		SlotBytes   hexBytes  `json:"slot_bytes_hex"`
		SigMessage  hexBytes  `json:"sig_message_hex"`
		AKPublic    hexBytes  `json:"ak_public_hex"`
		AKSig       hexBytes  `json:"ak_sig_hex"`
	}
	return vectorFile{
		Description: "Passphrase slot (contract §2.2, §2.3, Revision 2.1 point 2). KEK is kek.json \"production parameters\"; slot_params = canon(\"hort/v4/argon\\n\", salt, u32 t, u32 m, u8 p); wrapped_vk = AES-256-GCM(KEK, VK, aad = canon(\"hort/v4/slot\\n\", account_id, slot_id, u64 slot_version, slot_params)), ciphertext || tag; slot_bytes = canon(\"hort/v4/slot-bytes\\n\", slot_params, wrap_nonce, wrapped_vk); ak_sig = Ed25519_AK(canon(\"hort/v4/slot-sig\\n\", account_id, slot_id, u64 slot_version, slot_bytes)).",
		Vectors: []vec{{vecAccountID, vecVK, kek, PassphraseSlotID, version, vecSlotSalt, argonOf(params), slotParams,
			slotAAD(vecAccountID, PassphraseSlotID, version, slotParams), nonce, wrapped, slotBytes, msg,
			hexBytes(keys.AK.Public().(ed25519.PublicKey)), sig}},
	}
}

func passkeySlotVectors(t *testing.T) any {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	credentialID := fixed("credential-id", 20)
	prf := fixed("prf-output", PRFSize)
	kek := must(PasskeyKEK(prf, vecAccountID))
	nonce := fixed("nonce/passkey-slot", NonceSize)
	const version = 1
	slotID, slotParams := PasskeySlot(credentialID)
	credHash := sha256.Sum256(credentialID)
	wrapped := must(wrapVK(kek, vecVK, vecAccountID, slotID, version, slotParams, nonce))
	if vk := must(UnwrapVK(kek, nonce, wrapped, vecAccountID, slotID, version, slotParams)); !bytes.Equal(vk, vecVK) {
		t.Fatal("passkey slot does not round-trip")
	}
	slotBytes := SlotBytes(slotParams, nonce, wrapped)
	msg := SlotSigMessage(vecAccountID, slotID, version, slotBytes)
	type vec struct {
		AccountID    hexBytes `json:"account_id_hex"`
		VK           hexBytes `json:"vk_hex"`
		CredentialID hexBytes `json:"credential_id_hex"`
		CredHash     hexBytes `json:"cred_hash_hex"`
		PRF          hexBytes `json:"prf_output_hex"`
		KEK          hexBytes `json:"kek_hex"`
		SlotID       string   `json:"slot_id"`
		SlotVersion  uint64   `json:"slot_version"`
		SlotParams   hexBytes `json:"slot_params_hex"`
		AAD          hexBytes `json:"aad_hex"`
		Nonce        hexBytes `json:"wrap_nonce_hex"`
		Wrapped      hexBytes `json:"wrapped_vk_hex"`
		SlotBytes    hexBytes `json:"slot_bytes_hex"`
		SigMessage   hexBytes `json:"sig_message_hex"`
		AKPublic     hexBytes `json:"ak_public_hex"`
		AKSig        hexBytes `json:"ak_sig_hex"`
	}
	return vectorFile{
		Description: "Passkey slot (contract §2.2; encoding fixed by S6.2). cred_hash = SHA-256(credential ID); slot_id = \"passkey:\" || lowercase hex(cred_hash); slot_params = canon(\"hort/v4/passkey\\n\", cred_hash); KEK = HKDF(PRF output, account_id, hort/v4/kek-passkey) as in kek.json; wrapped_vk, slot_bytes and ak_sig as in slot.json.",
		Vectors: []vec{{vecAccountID, vecVK, credentialID, credHash[:], prf, kek, slotID, version, slotParams,
			slotAAD(vecAccountID, slotID, version, slotParams), nonce, wrapped, slotBytes, msg,
			hexBytes(keys.AK.Public().(ed25519.PublicKey)), ed25519.Sign(keys.AK, msg)}},
	}
}

func vecTime(s string) *time.Time {
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	at = at.UTC()
	return &at
}

func vecRevision(n int, at, op, field, key, value string) Revision {
	r := Revision{ID: fmt.Sprintf("%032x", n), Op: op, Field: field, Key: key, Value: value}
	if at != "" {
		r.RecordedAt = vecTime(at)
	}
	return r
}

func envelopeVectors(t *testing.T) any {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	type vec struct {
		Name      string   `json:"name"`
		EntryName string   `json:"entry_name"`
		Revision  Revision `json:"revision"`
		RK        hexBytes `json:"rk_hex"`
		AccountID hexBytes `json:"account_id_hex"`
		AAD       hexBytes `json:"aad_hex"`
		Nonce     hexBytes `json:"nonce_hex"`
		Plaintext string   `json:"plaintext"`
		Envelope  hexBytes `json:"envelope_hex"`
		Base64    string   `json:"envelope_base64"`
	}
	cases := []struct {
		name, entry string
		r           Revision
	}{
		{"set on the default field", "github-token", vecRevision(1, "2026-11-06T10:00:00Z", "set", "", "*:*", "ghp_example")},
		{"set on a named field with env and context", "db", vecRevision(2, "2026-11-06T10:00:00.000000001Z", "set", "password", "prod:heine", "s3cr3t ä")},
		{"describe", "db", vecRevision(3, "2026-11-06T10:00:01Z", "describe", "", "", "Postgres of tenant heine")},
		{"delete-entry", "db", vecRevision(4, "2026-11-06T10:00:02Z", "delete-entry", "", "", "")},
		{"imported revision without time", "legacy name", vecRevision(5, "", "set", "", "prod:*", "v1")},
	}
	var out []vec
	for i, c := range cases {
		nonce := fixed(fmt.Sprintf("nonce/revision/%d", i), NonceSize)
		env := must(sealRevision(keys.RK, vecAccountID, c.entry, c.r, nonce))
		name, r, err := OpenRevision(keys.RK, vecAccountID, c.r.ID, env)
		if err != nil || name != c.entry || r.ID != c.r.ID || r.Field != c.r.Field || r.Value != c.r.Value {
			t.Fatalf("%s: envelope does not round-trip: %v", c.name, err)
		}
		if _, _, err := OpenRevision(keys.RK, vecAccountID, fmt.Sprintf("%032x", 99), env); err == nil {
			t.Fatalf("%s: envelope opened under another revision ID", c.name)
		}
		plaintext := must(json.Marshal(revisionEnvelope{c.entry, c.r}))
		id, _ := hex.DecodeString(c.r.ID)
		out = append(out, vec{c.name, c.entry, c.r, keys.RK, vecAccountID, canon("hort/v4/rev\n", vecAccountID, id),
			nonce, string(plaintext), env, base64.StdEncoding.EncodeToString(env)})
	}
	return vectorFile{
		Description: "Revision envelope (contract §6.4): envelope = nonce(12) || AES-256-GCM(RK, plaintext, aad = canon(\"hort/v4/rev\\n\", account_id, revision id bytes)). plaintext is UTF-8 JSON {\"name\", \"revision\"}; \"field\" is omitted when empty.",
		Vectors:     out,
	}
}

func requestVectors(t *testing.T) any {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	requestID := hex.EncodeToString(fixed("request-id", 16))
	idBytes, _ := hex.DecodeString(requestID)
	// The single-field form an older Hort writes; readers take its field as the one entry of fields.
	single := `{"name":"openai","description":"API key for the summarizer","field":"","env":"prod","context":""}`
	nonce := fixed("nonce/request-meta", NonceSize)
	metaCT := must(sealEnvelope(keys.RK, nonce, []byte(single), requestMetaAAD(vecAccountID, idBytes)))
	singleMeta := RequestMeta{Name: "openai", Description: "API key for the summarizer", Fields: []string{""}, Env: "prod", Context: ""}
	if got := must(OpenRequestMeta(keys.RK, vecAccountID, requestID, metaCT)); !reflect.DeepEqual(got, singleMeta) {
		t.Fatal("single-field request meta does not read as fields")
	}
	fieldsID := hex.EncodeToString(fixed("request-id/fields", 16))
	fieldsIDBytes, _ := hex.DecodeString(fieldsID)
	meta := RequestMeta{Name: "stripe", Description: "Payments for the shop", Fields: []string{"client_id", "secret"}, Env: "prod", Context: ""}
	fieldsNonce := fixed("nonce/request-meta-fields", NonceSize)
	fieldsCT := must(sealRequestMeta(keys.RK, vecAccountID, fieldsID, meta, fieldsNonce))
	if got := must(OpenRequestMeta(keys.RK, vecAccountID, fieldsID, fieldsCT)); !reflect.DeepEqual(got, meta) {
		t.Fatal("request meta does not round-trip")
	}
	type metaVec struct {
		RequestID string      `json:"request_id"`
		Meta      RequestMeta `json:"meta"`
		RK        hexBytes    `json:"rk_hex"`
		AccountID hexBytes    `json:"account_id_hex"`
		AAD       hexBytes    `json:"aad_hex"`
		Nonce     hexBytes    `json:"nonce_hex"`
		Plaintext string      `json:"plaintext"`
		MetaCT    hexBytes    `json:"meta_ct_hex"`
		Base64    string      `json:"meta_ct_base64"`
	}
	type sigVec struct {
		Name          string   `json:"name"`
		HortAccount   string   `json:"hort_account"`
		HortDevice    string   `json:"hort_device"`
		AccountID     hexBytes `json:"account_id_hex"`
		DeviceField   hexBytes `json:"device_field_hex"`
		Method        string   `json:"method"`
		PathWithQuery string   `json:"path_with_query"`
		Timestamp     uint64   `json:"timestamp"`
		Body          string   `json:"body"`
		BodySHA256    hexBytes `json:"body_sha256_hex"`
		Message       hexBytes `json:"message_hex"`
		PublicKey     hexBytes `json:"public_key_hex"`
		Signature     hexBytes `json:"signature_hex"`
		HortSignature string   `json:"hort_signature"`
	}
	sign := func(name string, key ed25519.PrivateKey, device []byte, header, method, path string, ts uint64, body string) sigVec {
		msg := RequestMessage(vecAccountID, device, method, path, ts, []byte(body))
		sig := ed25519.Sign(key, msg)
		pub := key.Public().(ed25519.PublicKey)
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("%s: signature does not verify", name)
		}
		sum := sha256.Sum256([]byte(body))
		return sigVec{name, FormatAccountID(vecAccountID), header, vecAccountID, device, method, path, ts, body, sum[:], msg,
			hexBytes(pub), sig, base64.StdEncoding.EncodeToString(sig)}
	}
	plaintext := must(json.Marshal(meta))
	return vectorFile{
		Description: "Request meta (contract §7.2 step 3, tag per Kopf decision): meta_ct = nonce(12) || AES-256-GCM(RK, JSON meta, aad = canon(\"hort/v4/req-meta\\n\", account_id, request id bytes)). JSON meta is {name, description, fields, env, context} with 1 to 16 fields distinct by fold; the single-field form of an older Hort carries field instead of fields and reads as fields [field]. Request signature (contract §6.2): Ed25519 over canon(\"hort/v4/req\\n\", account_id, device id bytes or \"ak\", METHOD, PATH_WITH_QUERY, u64 timestamp, SHA-256(body)).",
		Vectors: map[string]any{
			"meta": []metaVec{
				{fieldsID, meta, keys.RK, vecAccountID, requestMetaAAD(vecAccountID, fieldsIDBytes), fieldsNonce, string(plaintext), fieldsCT, base64.StdEncoding.EncodeToString(fieldsCT)},
				{requestID, singleMeta, keys.RK, vecAccountID, requestMetaAAD(vecAccountID, idBytes), nonce, single, metaCT, base64.StdEncoding.EncodeToString(metaCT)},
			},
			"signature": []sigVec{
				sign("device key, POST with body", vecDeviceKey, vecDeviceID, hex.EncodeToString(vecDeviceID), "POST", "/api/v1/requests",
					1793872800, `{"id":"`+requestID+`","meta_ct":"`+base64.StdEncoding.EncodeToString(metaCT)+`"}`),
				sign("AK, GET with query and empty body", keys.AK, []byte(AKDeviceID), AKDeviceID, "GET", "/api/v1/revisions?after=0&limit=500", 1793872801, ""),
			},
		},
	}
}

func secretKeyVectors(t *testing.T) any {
	ones, ok := decode128(strings.Repeat("1", 25) + "0")
	if !ok {
		t.Fatal("ones fixture")
	}
	type keyVec struct {
		Name        string   `json:"name"`
		Key         hexBytes `json:"secret_key_hex"`
		DataSymbols string   `json:"data_symbols"`
		CheckSymbol string   `json:"check_symbol"`
		Display     string   `json:"display"`
	}
	type parseVec struct {
		Name  string   `json:"name"`
		Input string   `json:"input"`
		Key   hexBytes `json:"secret_key_hex,omitempty"`
		Error string   `json:"error,omitempty"`
	}
	type idVec struct {
		ID      hexBytes `json:"account_id_hex"`
		Display string   `json:"display"`
	}
	var keysOut []keyVec
	for _, k := range []struct {
		name string
		key  []byte
	}{{"all zero", make([]byte, 16)}, {"all 0xff", bytes.Repeat([]byte{0xff}, 16)}, {"symbols 1", ones}, {"fixture", vecSecretKey}} {
		d := FormatSecretKey(k.key)
		if back := must(ParseSecretKey(d)); !bytes.Equal(back, k.key) {
			t.Fatalf("%s does not round-trip", k.name)
		}
		keysOut = append(keysOut, keyVec{k.name, k.key, encode128(k.key), string(secretKeyCheck(k.key)), d})
	}
	display := FormatSecretKey(vecSecretKey)
	zero := FormatSecretKey(make([]byte, 16))
	onesDisplay := FormatSecretKey(ones)
	ok1 := func(name, input string, key []byte) parseVec {
		got, err := ParseSecretKey(input)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("%s: %q does not parse: %v", name, input, err)
		}
		return parseVec{Name: name, Input: input, Key: key}
	}
	bad := func(name, input string) parseVec {
		if _, err := ParseSecretKey(input); !errors.Is(err, ErrSecretKeyMistyped) {
			t.Fatalf("%s: %q accepted", name, input)
		}
		return parseVec{Name: name, Input: input, Error: ErrSecretKeyMistyped.Error()}
	}
	// A typo in one data symbol that the check symbol catches.
	typo := ""
	for i := 3; typo == "" && i < len(display); i++ {
		if display[i] == '-' {
			continue
		}
		for _, c := range crockford {
			cand := display[:i] + string(c) + display[i+1:]
			if byte(c) != display[i] {
				if _, err := ParseSecretKey(cand); errors.Is(err, ErrSecretKeyMistyped) {
					typo = cand
					break
				}
			}
		}
	}
	wrongCheck := display[:len(display)-1] + string(crockford[(strings.IndexByte(crockford, display[len(display)-1])+1)%32])
	parse := []parseVec{
		ok1("display form", display, vecSecretKey),
		ok1("lowercase", strings.ToLower(display), vecSecretKey),
		ok1("spaces instead of dashes", strings.ReplaceAll(display, "-", " "), vecSecretKey),
		ok1("no separators", strings.ReplaceAll(display, "-", ""), vecSecretKey),
		ok1("without the H4 prefix", display[3:], vecSecretKey),
		ok1("O typed for 0", strings.ReplaceAll(zero[3:], "0", "O"), make([]byte, 16)),
		ok1("I and l typed for 1", strings.Replace(strings.ReplaceAll(onesDisplay[3:], "1", "I"), "I", "l", 3), ones),
		bad("one data symbol mistyped", typo),
		bad("wrong check symbol", wrongCheck),
		bad("one symbol missing", display[:len(display)-3]+display[len(display)-2:]),
		bad("U is not in the alphabet", "U"+display[4:]),
	}
	idDisplay := FormatAccountID(vecAccountID)
	if back := must(ParseAccountID(idDisplay)); !bytes.Equal(back, vecAccountID) {
		t.Fatal("account id does not round-trip")
	}
	return vectorFile{
		Description: "Secret Key (contract §2.5) and account ID (§2.6). 16 bytes, MSB first, into 26 Crockford base32 symbols (0123456789ABCDEFGHJKMNPQRSTVWXYZ); the 26th symbol holds the last 3 bits and 2 zero bits. Check symbol = alphabet[SHA-256(\"hort/v4/sk-check\\n\" || key)[0] >> 3]. Display H4-6-5-5-5-5-check. Parsing: ASCII case-insensitive, dashes and spaces ignored, I and L read as 1, O as 0, H4 prefix optional; any failure is \"Secret Key mistyped\". Account ID: the same 26 symbols in lowercase, no check symbol.",
		Vectors: map[string]any{
			"secret_keys": keysOut,
			"parse":       parse,
			"account_ids": []idVec{{vecAccountID, idDisplay}, {make([]byte, 16), FormatAccountID(make([]byte, 16))}},
		},
	}
}

type valueJSON struct {
	Field string `json:"field"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type resolveJSON struct {
	Field   string  `json:"field"`
	Env     string  `json:"env"`
	Context string  `json:"context"`
	Value   *string `json:"value"`
}

type reductionCase struct {
	Name        string        `json:"name"`
	Revisions   []Revision    `json:"revisions"`
	HistoryIDs  []string      `json:"history_ids"`
	Values      []valueJSON   `json:"values"`
	Description string        `json:"description"`
	Visible     bool          `json:"visible"`
	Resolve     []resolveJSON `json:"resolve"`
}

func reduce(t *testing.T, name string, revisions []Revision, queries [][3]string) reductionCase {
	e := Entry{Revisions: revisions}
	ids := []string{}
	for _, r := range e.History() {
		ids = append(ids, r.ID)
	}
	values, desc, visible := e.Current()
	vals := []valueJSON{}
	for k, v := range values {
		vals = append(vals, valueJSON{k.Field, k.Key, v})
	}
	sort.Slice(vals, func(i, j int) bool {
		if vals[i].Field != vals[j].Field {
			return vals[i].Field < vals[j].Field
		}
		return vals[i].Key < vals[j].Key
	})
	res := []resolveJSON{}
	for _, q := range queries {
		var out *string
		if v, ok := e.Resolve(q[0], q[1], q[2]); ok {
			out = &v
		}
		res = append(res, resolveJSON{q[0], q[1], q[2], out})
	}
	// Arrival order must not matter.
	rev := append([]Revision(nil), revisions...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	v2, d2, vis2 := Entry{Revisions: rev}.Current()
	if len(v2) != len(values) || d2 != desc || vis2 != visible {
		t.Fatalf("%s: reduction depends on arrival order", name)
	}
	return reductionCase{name, revisions, ids, vals, desc, visible, res}
}

func reductionVectors(t *testing.T) any {
	cases := []reductionCase{
		reduce(t, "order: unknown time first, then UTC time with nanoseconds, then ID", []Revision{
			vecRevision(4, "2026-01-01T00:00:00.000000002Z", "set", "", "*:*", "latest by nanoseconds"),
			vecRevision(3, "2026-01-01T00:00:00.000000001Z", "set", "", "*:*", "tie, higher ID"),
			vecRevision(2, "2026-01-01T00:00:00.000000001Z", "set", "", "*:*", "tie, lower ID"),
			vecRevision(1, "", "set", "", "*:*", "imported without time"),
			vecRevision(5, "", "describe", "", "", "imported description"),
		}, [][3]string{{"", "", ""}}),
		reduce(t, "fields: values keyed by field and lookup key, resolution stays inside the field", []Revision{
			vecRevision(1, "2026-01-01T00:00:00Z", "set", "", "*:*", "default baseline"),
			vecRevision(2, "2026-01-01T00:00:01Z", "set", "password", "*:*", "password baseline"),
			vecRevision(3, "2026-01-01T00:00:02Z", "set", "password", "prod:*", "password prod"),
			vecRevision(4, "2026-01-01T00:00:03Z", "set", "password", "prod:heine", "password prod heine"),
			vecRevision(5, "2026-01-01T00:00:04Z", "set", "user", "prod:*", "user prod"),
		}, [][3]string{
			{"password", "prod", "heine"}, {"password", "prod", "other"}, {"password", "dev", "heine"},
			{"", "prod", "heine"}, {"user", "dev", ""}, {"user", "prod", "heine"}, {"missing", "", ""},
		}),
		reduce(t, "delete removes one field and lookup key only", []Revision{
			vecRevision(1, "2026-01-01T00:00:00Z", "set", "", "prod:*", "default prod"),
			vecRevision(2, "2026-01-01T00:00:01Z", "set", "password", "prod:*", "password prod"),
			vecRevision(3, "2026-01-01T00:00:02Z", "delete", "password", "prod:*", ""),
		}, [][3]string{{"password", "prod", ""}, {"", "prod", ""}}),
		reduce(t, "delete-entry clears every field and the description; describe does not revive; set revives only its value", []Revision{
			vecRevision(1, "2026-01-01T00:00:00Z", "set", "", "*:*", "old default"),
			vecRevision(2, "2026-01-01T00:00:01Z", "set", "password", "*:*", "old password"),
			vecRevision(3, "2026-01-01T00:00:02Z", "describe", "", "", "old description"),
			vecRevision(4, "2026-01-01T00:00:03Z", "delete-entry", "", "", ""),
			vecRevision(5, "2026-01-01T00:00:04Z", "describe", "", "", "new description"),
			vecRevision(6, "2026-01-01T00:00:05Z", "set", "password", "dev:*", "revived"),
		}, [][3]string{{"password", "dev", ""}, {"password", "", ""}, {"", "", ""}}),
		reduce(t, "delete-entry without a later set leaves the entry invisible", []Revision{
			vecRevision(1, "2026-01-01T00:00:00Z", "set", "", "*:*", "v"),
			vecRevision(2, "2026-01-01T00:00:01Z", "delete-entry", "", "", ""),
			vecRevision(3, "2026-01-01T00:00:02Z", "describe", "", "", "after delete"),
		}, [][3]string{{"", "", ""}}),
		reduce(t, "describe alone makes an entry visible without values", []Revision{
			vecRevision(1, "2026-01-01T00:00:00Z", "describe", "", "", "first"),
			vecRevision(2, "2026-01-01T00:00:01Z", "describe", "", "", "second"),
		}, [][3]string{{"", "", ""}}),
	}
	type appendVec struct {
		Name     string     `json:"name"`
		Existing []Revision `json:"existing"`
		Now      string     `json:"now"`
		Stamped  string     `json:"recorded_at"`
	}
	appendCase := func(name string, existing []Revision, now string) appendVec {
		e := Entry{Revisions: append([]Revision(nil), existing...)}
		e.appendAt(vecRevision(9, "", "set", "", "*:*", "new"), *vecTime(now))
		stamped := e.Revisions[len(e.Revisions)-1].RecordedAt.Format(time.RFC3339Nano)
		return appendVec{name, existing, now, stamped}
	}
	appends := []appendVec{
		appendCase("local clock ahead of every known revision: now", []Revision{
			vecRevision(1, "2026-01-01T00:00:00Z", "set", "", "*:*", "a"),
		}, "2026-01-01T00:00:05Z"),
		appendCase("known revision from a clock running ahead: newest + 1 ns", []Revision{
			vecRevision(1, "2026-01-01T00:10:00Z", "set", "", "*:*", "a"),
			vecRevision(2, "2026-01-01T00:20:00.5Z", "delete-entry", "", "", ""),
		}, "2026-01-01T00:00:05Z"),
		appendCase("equal time: newest + 1 ns", []Revision{
			vecRevision(1, "2026-01-01T00:00:05Z", "set", "", "*:*", "a"),
		}, "2026-01-01T00:00:05Z"),
		appendCase("revisions without time are ignored", []Revision{
			vecRevision(1, "", "set", "", "*:*", "imported"),
		}, "2026-01-01T00:00:05Z"),
	}
	return vectorFile{
		Description: "Reduction (contract §3.1-§3.3, Append rule §3.2). History order: unknown recorded_at first, then UTC time compared at nanosecond precision, then ID (byte-wise ascending). Values are keyed by (field, lookup key). Revisions are listed in arrival order, which must not matter. resolve: (F, E:C), then (F, E:*), then (F, *:*); empty env or context means *; value null = not found.",
		Vectors: map[string]any{
			"reduce": cases,
			"append": appends,
		},
	}
}

func foldVectors(t *testing.T) any {
	type foldVec struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Folded string `json:"folded"`
	}
	foldCase := func(name, input, want string) foldVec {
		if got := FoldKey(input); got != want {
			t.Fatalf("%s: FoldKey(%q) = %q, want %q", name, input, got, want)
		}
		if again := FoldKey(want); again != want {
			t.Fatalf("%s: folding is not idempotent: %q", name, again)
		}
		return foldVec{name, input, want}
	}
	folds := []foldVec{
		foldCase("ASCII", "DHL-Developer-Portal", "dhl-developer-portal"),
		foldCase("digits and punctuation stay", "PROD_2.eu:*", "prod_2.eu:*"),
		foldCase("umlauts", "ÄÖÜ-Prüfung", "äöü-prüfung"),
		foldCase("decomposed umlaut stays decomposed", "U\u0308ber", "u\u0308ber"),
		foldCase("capital sharp s becomes sharp s, never ss", "STRAẞE", "straße"),
		foldCase("sharp s stays", "Straße", "straße"),
		foldCase("dotted capital I", "İstanbul", "i\u0307stanbul"),
		foldCase("dotless i stays", "ışık", "ışık"),
		foldCase("capital sigma, no final-sigma rule", "ΟΔΥΣΣΕΥΣ", "οδυσσευσ"),
		foldCase("final sigma stays", "Οδυσσευς", "οδυσσευς"),
		foldCase("caseless script", "東京-ציון", "東京-ציון"),
	}

	type stored struct {
		Name     string   `json:"name"`
		Revision Revision `json:"revision"`
	}
	in := []stored{
		{"DHL-Developer-Portal", vecRevision(1, "2026-01-01T00:00:00Z", "set", "", "TEST:*", "old test")},
		{"dhl-developer-portal", vecRevision(2, "2026-01-01T00:00:01Z", "set", "", "test:*", "new test")},
		{"DHL-DEVELOPER-PORTAL", vecRevision(3, "2026-01-01T00:00:02Z", "describe", "", "", "Developer portal")},
		{"dhl-developer-portal", vecRevision(4, "2026-01-01T00:00:03Z", "set", "password", "Prod:Heine", "heine first")},
		{"DHL-Developer-Portal", vecRevision(5, "2026-01-01T00:00:04Z", "set", "password", "PROD:HEINE", "heine newest")},
		{"dhl-developer-portal", vecRevision(6, "2026-01-01T00:00:05Z", "set", "password", "prod:*", "prod")},
		{"DHL-Developer-Portal", vecRevision(7, "2026-01-01T00:00:06Z", "delete", "password", "PROD:*", "")},
		{"dhl-developer-portal", vecRevision(10, "2026-01-01T00:00:07Z", "set", "user", "test:HEINE", "env and context spelled from other values")},
		{"Other", vecRevision(8, "2026-01-01T00:00:00Z", "set", "", "*:*", "newer")},
		{"other", vecRevision(9, "", "set", "", "*:*", "imported without time")},
	}
	vaultOf := func(in []stored) *VaultData {
		d := &VaultData{Secrets: map[string]Entry{}}
		for _, s := range in {
			e := d.Secrets[s.Name]
			e.Revisions = append(e.Revisions, s.Revision)
			d.Secrets[s.Name] = e
		}
		return d
	}
	type entryVec struct {
		Name        string      `json:"name"`
		HistoryIDs  []string    `json:"history_ids"`
		Values      []valueJSON `json:"values"`
		Description string      `json:"description"`
		Visible     bool        `json:"visible"`
	}
	entriesOf := func(d *VaultData) []entryVec {
		out := []entryVec{}
		for name, e := range d.Entries() {
			c := reduce(t, name, e.Revisions, nil)
			out = append(out, entryVec{name, c.HistoryIDs, c.Values, c.Description, c.Visible})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}
	d := vaultOf(in)
	entries := entriesOf(d)
	reversed := append([]stored(nil), in...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	if fmt.Sprint(entriesOf(vaultOf(reversed))) != fmt.Sprint(entries) {
		t.Fatal("folded reduction depends on arrival order")
	}

	type resolveVec struct {
		Name    string  `json:"name"`
		Field   string  `json:"field"`
		Env     string  `json:"env"`
		Context string  `json:"context"`
		Value   *string `json:"value"`
	}
	resolves := []resolveVec{}
	for _, q := range [][4]string{
		{"dhl-DEVELOPER-portal", "", "Test", ""},
		{"DHL-Developer-Portal", "PASSWORD", "prod", "HEINE"},
		{"dhl-developer-portal", "Password", "PROD", "other"},
		{"OTHER", "", "", ""},
		{"missing", "", "", ""},
	} {
		var out *string
		_, e, _ := d.Entry(q[0])
		if v, ok := e.Resolve(q[1], q[2], q[3]); ok {
			out = &v
		}
		resolves = append(resolves, resolveVec{q[0], q[1], q[2], q[3], out})
	}

	type spellVec struct {
		Name       string `json:"name"`
		Field      string `json:"field"`
		Env        string `json:"env"`
		Context    string `json:"context"`
		WriteName  string `json:"write_name"`
		WriteField string `json:"write_field"`
		WriteKey   string `json:"write_key"`
	}
	spells := []spellVec{}
	for _, q := range [][4]string{
		{"dhl-developer-portal", "PASSWORD", "prod", "heine"},
		{"DHL-DEVELOPER-PORTAL", "", "test", ""},
		{"dhl-developer-portal", "user", "Dev", ""},
		{"dhl-developer-portal", "token", "prod", "x"},
		{"dhl-developer-portal", "token", "dev", "HEINE"},
		{"New-Secret", "", "", ""},
	} {
		name, e, _ := d.Entry(q[0])
		k := e.Spelling(ValueKey{q[1], MakeLookupKey(q[2], q[3])})
		spells = append(spells, spellVec{q[0], q[1], q[2], q[3], name, k.Field, k.Key})
	}

	return vectorFile{
		Description: "Case-insensitive keys. fold: the identity of a name, field, env or context, lowercase per code point with U+0130 -> i + U+0307; no normalization, no ss, no final-sigma rule. reduce: revisions stored under names that differ only in case form one entry holding all their revisions, shown under the name of its earliest revision in history order; values whose field and lookup key fold alike are one value; field, env and context are each spelled like the earliest set or delete whose part folds alike, across fields and partner parts; the newest value wins and the older ones stay in history. resolve: name, field, env and context compare folded. spell: a write lands on write_name, write_field and write_key, the existing spelling, or the given one for a new value.",
		Vectors: map[string]any{
			"fold": folds,
			"reduce": map[string]any{
				"stored":  in,
				"entries": entries,
				"resolve": resolves,
				"spell":   spells,
			},
		},
	}
}

func shareVectors(t *testing.T) any {
	keys := must(DeriveAccountKeys(vecVK, vecAccountID))
	shareID := hex.EncodeToString(fixed("share-id", 16))
	idBytes, _ := hex.DecodeString(shareID)
	linkKey := fixed("link-key", ShareLinkKeySize)

	type normVec struct {
		Name       string `json:"name"`
		Input      string `json:"input"`
		Normalized string `json:"normalized"`
	}
	normCase := func(name, input, want string) normVec {
		if got := NormalizeShareName(input); got != want {
			t.Fatalf("%s: NormalizeShareName(%q) = %q, want %q", name, input, got, want)
		}
		if again := NormalizeShareName(want); again != want {
			t.Fatalf("%s: normalization is not idempotent: %q", name, again)
		}
		return normVec{name, input, want}
	}
	normalize := []normVec{
		normCase("plain name", "Lars", "lars"),
		normCase("umlaut, precomposed", "Jörg Müller", "jörg müller"),
		normCase("umlaut, decomposed (NFD)", "Jo\u0308rg Mu\u0308ller", "jörg müller"),
		normCase("sharp s", "Strauß", "strauss"),
		normCase("capital sharp s", "STRAUẞ", "strauss"),
		normCase("ss spelled out", "STRAUSS", "strauss"),
		normCase("dotted capital I", "İlker", "i\u0307lker"),
		normCase("dotless i stays", "Işık", "işık"),
		normCase("capital sigma", "ΟΔΥΣΣΕΥΣ", "οδυσσευσ"),
		normCase("final sigma", "Οδυσσευς", "οδυσσευσ"),
		normCase("whitespace: trim and collapse, tab, no-break and ideographic space", " \tLars\u00a0 \u3000Müller\n", "lars müller"),
		normCase("fullwidth letters (NFKC)", "Ｌａｒｓ", "lars"),
		normCase("whitespace only", " \t\u00a0", ""),
	}
	if _, err := DeriveShareKeys("  \t", linkKey, shareID); err == nil {
		t.Fatal("empty name derived keys")
	}

	type keyVec struct {
		Name       string    `json:"name"`
		TestParams bool      `json:"test_params_only"`
		Input      string    `json:"input"`
		Normalized string    `json:"normalized"`
		NormHex    hexBytes  `json:"normalized_utf8_hex"`
		ShareID    string    `json:"share_id"`
		LinkKey    hexBytes  `json:"link_key_hex"`
		Argon      argonJSON `json:"argon"`
		A          hexBytes  `json:"argon_output_hex"`
		K          hexBytes  `json:"share_key_hex"`
		Enc        hexBytes  `json:"enc_key_hex"`
		Token      hexBytes  `json:"token_hex"`
		TokenB64   string    `json:"token_base64"`
		TokenHash  hexBytes  `json:"token_hash_hex"`
		HashB64    string    `json:"token_hash_base64"`
	}
	keyCase := func(name, input string, p ArgonParams, test bool) keyVec {
		a, k := func() ([]byte, []byte) {
			a, k, err := shareKey(input, linkKey, shareID, p)
			if err != nil {
				t.Fatal(err)
			}
			return a, k
		}()
		sk := must(deriveShareKeys(input, linkKey, shareID, p))
		sum := sha256.Sum256(sk.Token)
		n := NormalizeShareName(input)
		return keyVec{name, test, input, n, []byte(n), shareID, linkKey, argonOf(p), a, k, sk.Enc, sk.Token,
			base64.StdEncoding.EncodeToString(sk.Token), sum[:], base64.StdEncoding.EncodeToString(sum[:])}
	}
	keyVecs := []keyVec{
		keyCase("production parameters", "Jörg Müller", DefaultArgonParams(), false),
		keyCase("test parameters", "Jörg Müller", testArgon, true),
		keyCase("test parameters, another spelling of the same name gives the same keys", "  JO\u0308RG   müller ", testArgon, true),
	}
	if !bytes.Equal(keyVecs[1].Token, keyVecs[2].Token) || !bytes.Equal(keyVecs[1].Enc, keyVecs[2].Enc) {
		t.Fatal("two spellings of one name derive different keys")
	}
	if !bytes.Equal(must(DeriveShareKeys("Jörg Müller", linkKey, shareID)).Token, keyVecs[0].Token) {
		t.Fatal("DeriveShareKeys does not use production parameters")
	}
	if other := must(deriveShareKeys("Jörg Mueller", linkKey, shareID, testArgon)); bytes.Equal(other.Token, keyVecs[1].Token) {
		t.Fatal("another name derived the same token")
	}

	type ctVec struct {
		Name      string       `json:"name"`
		ShareID   string       `json:"share_id"`
		Secret    SharedSecret `json:"secret"`
		Enc       hexBytes     `json:"enc_key_hex"`
		AAD       hexBytes     `json:"aad_hex"`
		Nonce     hexBytes     `json:"nonce_hex"`
		Plaintext string       `json:"plaintext"`
		CT        hexBytes     `json:"ct_hex"`
		Base64    string       `json:"ct_base64"`
	}
	enc := keyVecs[1].Enc
	ctCase := func(i int, name string, s SharedSecret) ctVec {
		nonce := fixed(fmt.Sprintf("nonce/share/%d", i), NonceSize)
		ct := must(sealShare(enc, shareID, s, nonce))
		got := must(OpenShare(enc, shareID, ct))
		if got.Name != s.Name || got.Description != s.Description || len(got.Fields) != len(s.Fields) {
			t.Fatalf("%s: share does not round-trip", name)
		}
		if _, err := OpenShare(enc, fmt.Sprintf("%032x", 99), ct); err == nil {
			t.Fatalf("%s: share opened under another share ID", name)
		}
		if _, err := OpenShare(keyVecs[0].Enc, shareID, ct); err == nil {
			t.Fatalf("%s: share opened with another key", name)
		}
		return ctVec{name, shareID, s, enc, shareAAD(idBytes), nonce, string(must(json.Marshal(s))), ct, base64.StdEncoding.EncodeToString(ct)}
	}
	cts := []ctVec{
		ctCase(0, "default field only, empty description", SharedSecret{Name: "github-token", Fields: []SharedField{{"", "ghp_example"}}}),
		ctCase(1, "default and named fields", SharedSecret{Name: "db", Description: "Postgres of tenant heine",
			Fields: []SharedField{{"", "postgres://db"}, {"user", "heine"}, {"password", "s3cr3t ä"}}}),
	}
	for _, bad := range []SharedSecret{
		{Name: "db"},
		{Name: "", Fields: []SharedField{{"", "v"}}},
		{Name: "db", Fields: []SharedField{{"user", "a"}, {"user", "b"}}},
		{Name: "db", Fields: []SharedField{{"User", "a"}}},
	} {
		if _, err := sealShare(enc, shareID, bad, fixed("nonce/share/bad", NonceSize)); err == nil {
			t.Fatalf("sealed invalid share %+v", bad)
		}
	}

	type metaVec struct {
		ShareID   string    `json:"share_id"`
		Meta      shareMeta `json:"meta"`
		RK        hexBytes  `json:"rk_hex"`
		AccountID hexBytes  `json:"account_id_hex"`
		AAD       hexBytes  `json:"aad_hex"`
		Nonce     hexBytes  `json:"nonce_hex"`
		Plaintext string    `json:"plaintext"`
		MetaCT    hexBytes  `json:"meta_ct_hex"`
		Base64    string    `json:"meta_ct_base64"`
	}
	meta := shareMeta{Name: "db", Recipient: "Jörg Müller", Fields: []string{"", "user", "password"}}
	metaNonce := fixed("nonce/share-meta", NonceSize)
	metaCT := must(sealShareMeta(keys.RK, vecAccountID, shareID, meta, metaNonce))
	if got := must(openShareMeta(keys.RK, vecAccountID, shareID, metaCT)); got.Name != meta.Name || got.Recipient != meta.Recipient || len(got.Fields) != 3 {
		t.Fatal("share meta does not round-trip")
	}

	type linkVec struct {
		Name    string   `json:"name"`
		Link    string   `json:"link"`
		Origin  string   `json:"origin,omitempty"`
		ShareID string   `json:"share_id,omitempty"`
		LinkKey hexBytes `json:"link_key_hex,omitempty"`
		Error   string   `json:"error,omitempty"`
	}
	fragment := base64.RawURLEncoding.EncodeToString(linkKey)
	good := func(name, link, origin string) linkVec {
		o, id, key, err := ParseShareLink(link)
		if err != nil || o != origin || id != shareID || !bytes.Equal(key, linkKey) {
			t.Fatalf("%s: %q does not parse: %v", name, link, err)
		}
		return linkVec{Name: name, Link: link, Origin: origin, ShareID: shareID, LinkKey: linkKey}
	}
	bad := func(name, link string) linkVec {
		if _, _, _, err := ParseShareLink(link); err == nil {
			t.Fatalf("%s: %q accepted", name, link)
		}
		return linkVec{Name: name, Link: link, Error: errShareLink.Error()}
	}
	links := []linkVec{
		good("hort.pm", "https://hort.pm/s/"+shareID+"#"+fragment, "https://hort.pm"),
		good("self-hosted with port", "https://vault.example.com:8443/s/"+shareID+"#"+fragment, "https://vault.example.com:8443"),
		bad("http", "http://hort.pm/s/"+shareID+"#"+fragment),
		bad("query string", "https://hort.pm/s/"+shareID+"?x=1#"+fragment),
		bad("no fragment", "https://hort.pm/s/"+shareID),
		bad("padded fragment", "https://hort.pm/s/"+shareID+"#"+fragment+"="),
		bad("short key", "https://hort.pm/s/"+shareID+"#"+fragment[:42]),
		bad("uppercase share ID", "https://hort.pm/s/"+strings.ToUpper(shareID)+"#"+fragment),
		bad("other path", "https://hort.pm/r/"+shareID+"#"+fragment),
	}

	return vectorFile{
		Description: "Share by link. Link: https://<origin>/s/<share ID, 16 bytes lowercase hex>#<link key, 32 bytes unpadded base64url>. normalize: NFKC, lowercase per code point (U+0130 -> i + U+0307), ς -> σ, ß and ẞ -> ss, NFKC, Unicode White_Space runs collapsed to one space and trimmed. A = Argon2id(UTF-8 normalized name, salt = share ID bytes, t, m, p, 32); K = HKDF(A XOR link key, share ID bytes, hort/v4/share); enc = HKDF(K, share ID bytes, hort/v4/share-enc); token = HKDF(K, share ID bytes, hort/v4/share-token); token_hash = SHA-256(token). ct = nonce(12) || AES-256-GCM(enc, JSON {name, description, fields: [{field, value}]}, aad = canon(\"hort/v4/share-ct\\n\", share ID bytes)). meta_ct = nonce(12) || AES-256-GCM(RK, JSON {name, recipient, fields: [field]}, aad = canon(\"hort/v4/share-meta\\n\", account_id, share ID bytes)).",
		Vectors: map[string]any{
			"normalize": normalize,
			"keys":      keyVecs,
			"ct":        cts,
			"meta": []metaVec{{shareID, meta, keys.RK, vecAccountID, shareMetaAAD(vecAccountID, idBytes), metaNonce,
				string(must(json.Marshal(meta))), metaCT, base64.StdEncoding.EncodeToString(metaCT)}},
			"link": links,
		},
	}
}
