package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type ArgonParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	DefaultArgonParams     = ArgonParams{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
)

func ArgonHash(password string, p ArgonParams) ([]byte, error) {
	n, err := RandomBytes(uint(p.saltLength))
	if err != nil {
		return nil, fmt.Errorf("failed to get random bytes: %w", err)
	}

	return argon2.IDKey([]byte(password), n, p.iterations, p.memory, p.parallelism, p.keyLength), nil
}

func ArgonCompareHash(password, encodedPassword string) (bool, error) {
	p, salt, hash, err := decodeHash(encodedPassword)
	if err != nil {
		return false, fmt.Errorf("failed to decode argon2 hash: %w", err)
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

func decodeHash(encodedHash string) (params ArgonParams, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return ArgonParams{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err = fmt.Sscanf(vals[2], "v=%d", &version); err != nil {
		return ArgonParams{}, nil, nil, fmt.Errorf("failed to scan argon2 version: %w", err)
	}

	if version != argon2.Version {
		return ArgonParams{}, nil, nil, ErrIncompatibleVersion
	}

	var p ArgonParams
	if _, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); err != nil {
		return ArgonParams{}, nil, nil, fmt.Errorf("failed to scan argon2 params: %w", err)
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return ArgonParams{}, nil, nil, fmt.Errorf("failed to decode argon2 salt: %w", err)
	}

	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return ArgonParams{}, nil, nil, fmt.Errorf("failed to decode argon2 hash: %w", err)
	}

	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}
