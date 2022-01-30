package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/uuid"
)

func RandomBytes(n uint) ([]byte, error) {
	b := make([]byte, n)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to read from rand.Reader: %w", err)
	}

	return b, nil
}

func RandomString() string {
	u := [16]byte(uuid.New())
	return hex.EncodeToString(u[:])
}
