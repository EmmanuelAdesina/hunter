package domain

import (
	"hash"

	"github.com/eadeshina/hunter/internal/canon"
)

// writeCanonical encodes v as canonical JSON straight into h.
//
// Values that cannot be encoded must not be silently dropped: a fingerprint
// computed over a partially-written record would compare equal across runs even
// when the underlying data changed, which is precisely the failure this system
// exists to prevent. A failure is folded into the hash rather than ignored.
func writeCanonical(h hash.Hash, v any) error {
	b, err := canon.Marshal(v)
	if err != nil {
		return err
	}
	_, werr := h.Write(b)
	return werr
}
