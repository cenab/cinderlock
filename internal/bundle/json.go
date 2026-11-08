package bundle

import (
	"bytes"
	"errors"

	"github.com/cenab/cinderlock/internal/spec"
)

func DecodeJSON(b []byte, out any) error { return strictJSON(b, out, false) }

func strictJSON(b []byte, out any, canonical bool) error {
	if len(b) == 0 || int64(len(b)) > MaxMetadataBytes || b[0] != '{' {
		return errors.New("invalid or oversized JSON metadata")
	}
	c, err := spec.CanonicalRaw(b)
	if err != nil {
		return err
	}
	if canonical && !bytes.Equal(c, b) {
		return errors.New("signed metadata is not canonical JSON")
	}
	return spec.Decode(b, out)
}
