package spec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const MaxDocumentBytes = 16 << 20

type Error struct {
	Code    int
	Message string
	Cause   error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }
func Err(code int, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 19
}
func Hash(data []byte) string { h := sha256.Sum256(data); return "sha256:" + hex.EncodeToString(h[:]) }
func Canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return CanonicalRaw(b)
}
func Digest(v any) (string, error) {
	b, e := Canonical(v)
	if e != nil {
		return "", e
	}
	return Hash(b), nil
}

// CanonicalRaw validates the restricted integer-only profile before RFC 8785 encoding.
func CanonicalRaw(b []byte) ([]byte, error) {
	if len(b) > MaxDocumentBytes || !utf8.Valid(b) {
		return nil, Err(2, "document exceeds limits or is not UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := tokens(d, 0); e != nil {
		return nil, e
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, Err(2, "trailing JSON content")
	}
	return jsoncanonicalizer.Transform(b)
}
func tokens(d *json.Decoder, depth int) error {
	if depth > 64 {
		return Err(2, "document nesting exceeds limit")
	}
	t, e := d.Token()
	if e != nil {
		return Err(2, "invalid JSON: %v", e)
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return Err(2, "duplicate or invalid JSON key %v", k)
				}
				seen[s] = true
				if e := tokens(d, depth+1); e != nil {
					return e
				}
			}
			x, e := d.Token()
			if e != nil || x != json.Delim('}') {
				return Err(2, "invalid JSON object")
			}
		case '[':
			for d.More() {
				if e := tokens(d, depth+1); e != nil {
					return e
				}
			}
			x, e := d.Token()
			if e != nil || x != json.Delim(']') {
				return Err(2, "invalid JSON array")
			}
		default:
			return Err(2, "unexpected JSON delimiter")
		}
	case json.Number:
		n, e := strconv.ParseInt(string(v), 10, 64)
		if e != nil || n > 9007199254740991 || n < -9007199254740991 {
			return Err(2, "numbers must be safe-range integers")
		}
	}
	return nil
}
func Decode(b []byte, out any) error {
	if len(b) > MaxDocumentBytes {
		return Err(2, "document exceeds size limit")
	}
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 {
		return Err(2, "empty document")
	}
	if trim[0] != '{' && trim[0] != '[' {
		var node yaml.Node
		dec := yaml.NewDecoder(bytes.NewReader(b))
		if e := dec.Decode(&node); e != nil {
			return Err(2, "invalid YAML: %v", e)
		}
		var extra yaml.Node
		if e := dec.Decode(&extra); e != io.EOF {
			return Err(2, "only one YAML document is allowed")
		}
		v, e := yamlValue(&node, 0)
		if e != nil {
			return e
		}
		b, e = json.Marshal(v)
		if e != nil {
			return e
		}
	}
	if _, e := CanonicalRaw(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return Err(2, "invalid document: %v", e)
	}
	return exactFields(b, reflect.TypeOf(out))
}

func exactFields(b []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return err
		}
		allowed := map[string]reflect.Type{}
		var collect func(reflect.Type)
		collect = func(t reflect.Type) {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if !f.IsExported() {
					continue
				}
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name == "-" {
					continue
				}
				if f.Anonymous && name == "" {
					ft := f.Type
					for ft.Kind() == reflect.Pointer {
						ft = ft.Elem()
					}
					if ft.Kind() == reflect.Struct {
						collect(ft)
						continue
					}
				}
				if name == "" {
					name = f.Name
				}
				allowed[name] = f.Type
			}
		}
		collect(typ)
		for name, value := range fields {
			ft, ok := allowed[name]
			if !ok {
				return Err(2, "unknown or incorrectly cased field %q", name)
			}
			if !bytes.Equal(value, []byte("null")) {
				if err := exactFields(value, ft); err != nil {
					return err
				}
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(b, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if err := json.Unmarshal(b, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
func yamlValue(n *yaml.Node, depth int) (any, error) {
	if depth > 64 || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return nil, Err(2, "YAML aliases/anchors or excessive nesting are unsupported")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, Err(2, "invalid YAML document")
		}
		return yamlValue(n.Content[0], depth+1)
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return nil, Err(2, "custom YAML mapping tags are unsupported")
		}
		m := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Tag != "!!str" || k.Anchor != "" {
				return nil, Err(2, "YAML keys must be strings")
			}
			if _, ok := m[k.Value]; ok {
				return nil, Err(2, "duplicate YAML key %q", k.Value)
			}
			v, e := yamlValue(n.Content[i+1], depth+1)
			if e != nil {
				return nil, e
			}
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return nil, Err(2, "custom YAML sequence tags are unsupported")
		}
		a := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, e := yamlValue(c, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			if n.Value == "true" {
				return true, nil
			}
			if n.Value == "false" {
				return false, nil
			}
		case "!!int":
			x, e := strconv.ParseInt(n.Value, 10, 64)
			if e == nil {
				return x, nil
			}
		}
	}
	return nil, Err(2, "unsupported or ambiguous YAML value at line %d", n.Line)
}
func Read(path string, out any) error {
	f, e := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > MaxDocumentBytes {
		return Err(2, "document must be a bounded regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxDocumentBytes+1))
	if e != nil {
		return e
	}
	return Decode(b, out)
}
func Write(path string, v any) error {
	b, e := Canonical(v)
	if e != nil {
		return e
	}
	if len(b) >= MaxDocumentBytes {
		return Err(2, "document with trailing newline exceeds size limit")
	}
	return WriteBytes(path, append(b, '\n'))
}
func WriteBytes(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	ok = true
	return nil
}
