package api

import (
	"net/http"
	"net/url"
	"strings"
)

// Invitation is one entry of the operator's list; UsedAt is nil while open.
type Invitation struct {
	ID        string  `json:"id"`
	CreatedAt int64   `json:"created_at"`
	UsedAt    *int64  `json:"used_at"`
	AccountID *string `json:"account_id"`
}

// CreateInvitation creates a single-use invitation and returns its ID and
// code; the server keeps only a hash of the code.
func CreateInvitation(server, adminToken string) (id, code string, err error) {
	var out struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	err = adminRequest("POST", server, "/invitations", adminToken, &out)
	return out.ID, out.Code, err
}

// ListInvitations returns every open and used invitation, never a code.
func ListInvitations(server, adminToken string) ([]Invitation, error) {
	var out struct {
		Invitations []Invitation `json:"invitations"`
	}
	err := adminRequest("GET", server, "/invitations", adminToken, &out)
	return out.Invitations, err
}

// RevokeInvitation deletes an open invitation by its ID.
func RevokeInvitation(server, adminToken, id string) error {
	return adminRequest("POST", server, "/invitations/"+url.PathEscape(id)+"/revoke", adminToken, nil)
}

// adminRequest sends an operator request with the server's ADMIN_TOKEN.
func adminRequest(method, server, path, adminToken string, out any) error {
	req, err := http.NewRequest(method, strings.TrimRight(server, "/")+"/api/v1"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Hort-Admin-Token", adminToken)
	return send(req, out)
}
