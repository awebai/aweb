package a2a

import (
	"errors"
	"fmt"
	"io"
	"math"
)

// ErrBodyTooLarge identifies a body exceeding the caller's byte limit.
var ErrBodyTooLarge = errors.New("HTTP body exceeds its byte limit")

// ReadBoundedBody reads at most maxBytes+1 and refuses overflow before a caller
// decodes the prefix (docs/a2a.md:1047-1051). The caller owns closing the reader.
// A complete body exactly at the limit remains valid.
func ReadBoundedBody(body io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return nil, errors.New("HTTP body limit is outside the supported range. Configure a non-negative limit below the maximum int64 value and retry.")
	}
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("HTTP body could not be read: %w. Check the sender connection and retry with a complete body.", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes). Reduce the body to this limit before retrying.", ErrBodyTooLarge, maxBytes)
	}
	return data, nil
}
