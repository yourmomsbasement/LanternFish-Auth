package gate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Sealer encrypts secrets the Gate must keep (the device CA key, Roku
// secrets) under the master key, which lives outside the data file.
type Sealer struct {
	aead cipher.AEAD
}

func NewSealer(masterKey []byte) (*Sealer, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext. purpose is bound as associated data, so a sealed
// value cannot be moved to another record or field.
func (s *Sealer) Seal(purpose string, plaintext []byte) string {
	nonce := randomBytes(s.aead.NonceSize())
	out := s.aead.Seal(nonce, nonce, plaintext, []byte(purpose))
	return base64.StdEncoding.EncodeToString(out)
}

func (s *Sealer) Open(purpose, sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, err
	}
	n := s.aead.NonceSize()
	if len(raw) < n+s.aead.Overhead() {
		return nil, errors.New("sealed value too short")
	}
	return s.aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
}

// GenerateMasterKey returns a new random master key, base64 encoded.
func GenerateMasterKey() string {
	return base64.StdEncoding.EncodeToString(randomBytes(32))
}

// LoadMasterKey reads the master key from, in order of preference, a DPAPI
// protected file (Windows), a file such as a Docker secret, or the
// environment variable itself.
func LoadMasterKey(dpapiFile, file, env string) ([]byte, error) {
	switch {
	case dpapiFile != "":
		blob, err := os.ReadFile(dpapiFile)
		if err != nil {
			return nil, err
		}
		key, err := dpapiUnprotect(blob)
		if err != nil {
			return nil, fmt.Errorf("unprotect %s: %w", dpapiFile, err)
		}
		return key, nil
	case file != "":
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return DecodeMasterKey(string(raw))
	case env != "":
		return DecodeMasterKey(env)
	}
	return nil, errors.New("no master key: set LANTERNFISH_MASTER_KEY_FILE, LANTERNFISH_MASTER_KEY_DPAPI_FILE or LANTERNFISH_MASTER_KEY (generate one with `lanternfish-gate gen-master-key`)")
}

func DecodeMasterKey(s string) ([]byte, error) {
	key, err := decodeB64(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("master key is not base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// decodeB64 accepts standard or URL-safe base64, with or without padding.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}
