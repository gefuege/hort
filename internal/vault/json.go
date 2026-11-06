package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// strictJSON rejects duplicate object keys as well as unknown fields and trailing
// data: none can be silently discarded on a read-modify-write of the vault.
func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func(reflect.Type) error
	walk = func(typ reflect.Type) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if tok == nil && typ.Kind() != reflect.Pointer {
			return fmt.Errorf("unexpected null in vault payload")
		}
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				fields := map[string]reflect.Type{}
				optional := map[string]bool{}
				if typ.Kind() == reflect.Struct {
					for i := 0; i < typ.NumField(); i++ {
						f := typ.Field(i)
						name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
						fields[name] = f.Type
						optional[name] = opts == "omitempty"
					}
				}
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						return err
					}
					key := k.(string)
					if seen[key] {
						return fmt.Errorf("duplicate JSON field %q", key)
					}
					seen[key] = true
					var child reflect.Type
					if typ.Kind() == reflect.Map {
						child = typ.Elem()
					} else if typ.Kind() == reflect.Struct {
						child = fields[key]
					}
					if child == nil {
						return fmt.Errorf("unexpected JSON field %q", key)
					}
					if err := walk(child); err != nil {
						return err
					}
				}
				for field := range fields {
					if !seen[field] && !optional[field] {
						return fmt.Errorf("missing JSON field %q", field)
					}
				}
			case '[':
				if typ.Kind() != reflect.Slice {
					return fmt.Errorf("unexpected JSON array")
				}
				for dec.More() {
					if err := walk(typ.Elem()); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected JSON delimiter")
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
