package vault

import "fmt"

// v3Vault is the decrypted content of a v3 vault, read only by `hort migrate`.
type v3Vault struct {
	Version  int              `json:"version"`
	SourceID string           `json:"source_id"`
	Secrets  map[string]Entry `json:"secrets"`
}

func decodeV3(raw []byte) (*v3Vault, error) {
	var d v3Vault
	if err := strictJSON(raw, &d); err != nil {
		return nil, err
	}
	if d.Version != 3 || !validID(d.SourceID) {
		return nil, fmt.Errorf("invalid v3 vault content")
	}
	if err := validateSecrets(d.Secrets, false); err != nil {
		return nil, err
	}
	return &d, nil
}
