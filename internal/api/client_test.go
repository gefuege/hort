package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientFollowsNoRedirect(t *testing.T) {
	reached := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	_, _, err := FetchSlot(srv.URL, make([]byte, 16))
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusFound {
		t.Fatalf("redirect answer: %v", err)
	}
	if reached {
		t.Fatal("the client followed the redirect")
	}
}
