package update

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
)

// trustedKeys are the project's release signing keys, built in so that every
// Gate can verify official releases without any setup.
//
//go:embed trusted-keys
var trustedKeys []byte

// BuiltInKeys returns the release keys built into this binary.
func BuiltInKeys() ([]PublicKey, error) {
	keys, err := ParsePublicKeys(trustedKeys)
	if err != nil {
		return nil, fmt.Errorf("built-in release keys: %w", err)
	}
	for i := range keys {
		if keys[i].Comment == "" {
			keys[i].Comment = "built-in key " + KeyID(keys[i].Key)
		}
	}
	return keys, nil
}

// TrustedKeys returns the built-in keys plus any in localPath (which may
// be missing). It fails only if a file is malformed or there are no keys.
func TrustedKeys(localPath string) ([]PublicKey, error) {
	keys, err := BuiltInKeys()
	if err != nil {
		return nil, err
	}
	if localPath != "" {
		data, err := os.ReadFile(localPath)
		switch {
		case err == nil:
			local, err := ParsePublicKeys(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", localPath, err)
			}
			keys = append(keys, local...)
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("this build has no release signing keys, and %s adds none", localPath)
	}
	return keys, nil
}
