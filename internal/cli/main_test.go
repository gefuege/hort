package cli

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/gefuege/hort/internal/api"
)

type noNetwork struct{}

func (noNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in tests")
}

// No test reaches a real server; the remote integration test sets its own client.
func TestMain(m *testing.M) {
	api.HTTPClient = &http.Client{Transport: noNetwork{}}
	os.Exit(m.Run())
}
