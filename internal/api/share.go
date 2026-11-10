package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// WrongShareToken is a 403 of a recipient share endpoint: the name did not
// give the share's access token. TriesLeft counts down to the destroying try.
type WrongShareToken struct {
	TriesLeft int
}

func (e *WrongShareToken) Error() string { return "wrong share token" }

// OpenShare fetches the ciphertext of share id from origin, the origin of the
// share link. A 404 comes back as *Error: the share is unknown or has ended.
func OpenShare(origin, id string, token []byte) ([]byte, error) {
	var out struct {
		CT []byte `json:"ct"`
	}
	if err := shareRequest("POST", origin, "/shares/"+id+"/open", token, &out); err != nil {
		return nil, err
	}
	return out.CT, nil
}

// DeleteShare takes the share: the server deletes its ciphertext.
func DeleteShare(origin, id string, token []byte) error {
	return shareRequest("DELETE", origin, "/shares/"+id, token, nil)
}

// shareRequest sends a recipient request; only the share ID and the access
// token leave the client, never the link key. id is hex, so it needs no escaping.
func shareRequest(method, origin, path string, token []byte, out any) error {
	req, err := http.NewRequest(method, strings.TrimRight(origin, "/")+"/api/v1"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Hort-Share-Token", base64.StdEncoding.EncodeToString(token))
	err = send(req, out)
	var apiErr *Error
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
		var body struct {
			TriesLeft int `json:"tries_left"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(apiErr.Message, "server: ")), &body) == nil {
			return &WrongShareToken{TriesLeft: body.TriesLeft}
		}
	}
	return err
}
