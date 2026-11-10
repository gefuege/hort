package mcp

import "testing"

func TestTupleIsTheSetOfFields(t *testing.T) {
	a := makeTuple("Stripe", []string{"client_id", "SECRET"}, "Prod", "")
	if b := makeTuple("stripe", []string{"secret", "Client_ID"}, "prod", ""); a != b {
		t.Fatalf("same set in another order and case: %+v != %+v", a, b)
	}
	if c := makeTuple("stripe", []string{"secret"}, "prod", ""); a == c {
		t.Fatal("a subset is the same request")
	}
	if makeTuple("x", []string{""}, "", "") == makeTuple("x", []string{"token"}, "", "") {
		t.Fatal("default field and a named field are the same request")
	}
}
