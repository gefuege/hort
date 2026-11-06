package vault

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeLimitMatchesSealedPlaintext(t *testing.T) {
	name := strings.Repeat("n", MaxNameBytes)
	rev := setRev("", "*:*", "")
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	rev.ID = id
	base, err := EnvelopePlaintext(name, rev)
	if err != nil {
		t.Fatal(err)
	}
	// <, > and & become six bytes each under json.Marshal; the check must count that.
	rev.Value = strings.Repeat("<&>", (MaxEnvelopeBytes-envelopeOverhead-len(base))/18)
	if err := ValidateWrite(name, rev); err != nil {
		t.Fatalf("value at the limit refused: %v", err)
	}
	rk, account, nonce := make([]byte, 32), make([]byte, 16), make([]byte, NonceSize)
	longest := time.Date(2000, 1, 1, 0, 0, 0, 123456789, time.UTC)
	sealedRev := rev
	sealedRev.RecordedAt = &longest
	envelope, err := sealRevision(rk, account, name, sealedRev, nonce)
	if err != nil {
		t.Fatal(err)
	}
	idBytes, err := decodeID(id)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := openEnvelope(rk, envelope, canon("hort/v4/rev\n", account, idBytes))
	if err != nil {
		t.Fatal(err)
	}
	measured, err := EnvelopePlaintext(name, rev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(measured, sealed) {
		t.Fatalf("measured plaintext differs from the sealed one: %d vs %d bytes", len(measured), len(sealed))
	}
	if len(envelope) > MaxEnvelopeBytes {
		t.Fatalf("sealed envelope is %d bytes", len(envelope))
	}
	rev.Value += strings.Repeat("<", 6)
	if err := ValidateWrite(name, rev); err == nil {
		t.Fatal("value over the limit accepted")
	}
}

func TestValidateRefusesInvalidUTF8Scope(t *testing.T) {
	for _, key := range []string{"\xff:*", "*:a\xffb"} {
		if err := ValidateWrite("t", setRev("", key, "v")); err == nil {
			t.Errorf("accepted key %q", key)
		}
	}
}
