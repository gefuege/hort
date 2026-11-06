package api

// Request states as the server reports them (server/README.md, agent requests).
const (
	RequestPending   = "pending"
	RequestFulfilled = "fulfilled"
	RequestDeclined  = "declined"
	RequestExpired   = "expired"
)

// RequestState is the answer of GET /requests/{id}; RevisionIDs is empty
// unless the request is fulfilled.
type RequestState struct {
	Status      string   `json:"status"`
	MetaCT      []byte   `json:"meta_ct"`
	RevisionIDs []string `json:"revision_ids"`
}

// PendingRequest is one entry of GET /requests?status=pending.
type PendingRequest struct {
	ID     string `json:"id"`
	MetaCT []byte `json:"meta_ct"`
}

// CreateRequest registers an agent request; id is 16 random bytes in hex.
func (c Client) CreateRequest(id string, metaCT []byte) error {
	return c.Do("POST", "/requests", map[string]any{"id": id, "meta_ct": metaCT}, nil)
}

// GetRequest reads one request. id is hex, so it needs no escaping.
func (c Client) GetRequest(id string) (RequestState, error) {
	var out RequestState
	err := c.Do("GET", "/requests/"+id, nil, &out)
	return out, err
}

// PendingRequests lists up to 50 pending requests, oldest first.
func (c Client) PendingRequests() ([]PendingRequest, error) {
	var out struct {
		Requests []PendingRequest `json:"requests"`
	}
	err := c.Do("GET", "/requests?status=pending", nil, &out)
	return out.Requests, err
}

// DeclineRequest declines a pending request.
func (c Client) DeclineRequest(id string) error {
	return c.Do("POST", "/requests/"+id+"/decline", nil, nil)
}
