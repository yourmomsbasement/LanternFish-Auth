// Package update signs and verifies Lanternfish releases, and installs them.
//
// A release carries a manifest (lanternfish-release.json) listing every file
// with its SHA-256 and size, and a detached Ed25519 signature over it
// (lanternfish-release.json.sig). The signing key stays offline with the
// administrator, encrypted under a passphrase; CI only builds and lists the
// files. Installations trust the public keys in /etc/lanternfish/release-keys.
//
// SECURITY: the manifest names its own version, and a manifest is only
// accepted for the release tag it claims, so an old signed release can't be
// replayed as a new one; installs refuse anything not newer than what runs.
package update

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ManifestName  = "lanternfish-release.json"
	SignatureName = "lanternfish-release.json.sig"
	Product       = "lanternfish-gate"

	signContext  = "lanternfish-release/v1\n"
	publicPrefix = "lfrk1"
	keyFileType  = "lanternfish-release-key/v1"
)

// kdfIterations protects the signing key's passphrase; tests lower it.
var kdfIterations = 600000

// Manifest lists a release's files.
type Manifest struct {
	Schema    int       `json:"schema"`
	Product   string    `json:"product"`
	Version   string    `json:"version"` // without the leading "v"
	Published time.Time `json:"published"`
	Files     []File    `json:"files"`
}

type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Signature struct {
	KeyID string `json:"key_id"`
	Sig   string `json:"signature"`
}

// PublicKey is a trusted release key.
type PublicKey struct {
	Key     ed25519.PublicKey
	Comment string
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// FormatPublicKey renders a key as one line for a release-keys file.
func FormatPublicKey(pub ed25519.PublicKey, comment string) string {
	return strings.TrimSpace(publicPrefix + " " + base64.StdEncoding.EncodeToString(pub) + " " + comment)
}

// ParsePublicKeys reads a release-keys file: one "lfrk1 <base64> [comment]"
// per line; blank lines and # comments are ignored.
func ParsePublicKeys(data []byte) ([]PublicKey, error) {
	var keys []PublicKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != publicPrefix {
			return nil, fmt.Errorf("line %d: expected %q followed by a base64 key", n, publicPrefix)
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("line %d: not an Ed25519 public key", n)
		}
		keys = append(keys, PublicKey{Key: raw, Comment: strings.Join(f[2:], " ")})
	}
	return keys, sc.Err()
}

func LoadPublicKeys(path string) ([]PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := ParsePublicKeys(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s holds no keys", path)
	}
	return keys, nil
}

// ---- Private key file ----

type keyFile struct {
	Type       string `json:"type"`
	Public     string `json:"public"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Sealed     string `json:"sealed_seed"`
}

// GenerateKey returns a new signing key, encrypted under passphrase
// (PBKDF2-SHA256, AES-256-GCM), and its public key.
func GenerateKey(passphrase string) (file []byte, pub ed25519.PublicKey, err error) {
	if len(passphrase) < 12 {
		return nil, nil, errors.New("use a passphrase of at least 12 characters")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	aead, err := keyAEAD(passphrase, salt, kdfIterations)
	if err != nil {
		return nil, nil, err
	}
	kf := keyFile{Type: keyFileType, Public: base64.StdEncoding.EncodeToString(pub), KDF: "pbkdf2-sha256",
		Iterations: kdfIterations, Salt: base64.StdEncoding.EncodeToString(salt),
		Nonce:  base64.StdEncoding.EncodeToString(nonce),
		Sealed: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, priv.Seed(), []byte(keyFileType)))}
	file, err = json.MarshalIndent(kf, "", "  ")
	return append(file, '\n'), pub, err
}

func keyAEAD(passphrase string, salt []byte, iterations int) (cipher.AEAD, error) {
	k, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// OpenKey decrypts a key file.
func OpenKey(file []byte, passphrase string) (ed25519.PrivateKey, error) {
	var kf keyFile
	if err := json.Unmarshal(file, &kf); err != nil || kf.Type != keyFileType || kf.KDF != "pbkdf2-sha256" {
		return nil, errors.New("not a Lanternfish release key file")
	}
	if kf.Iterations < 100000 || kf.Iterations > 10000000 {
		return nil, errors.New("key file has an unreasonable iteration count")
	}
	salt, err1 := base64.StdEncoding.DecodeString(kf.Salt)
	nonce, err2 := base64.StdEncoding.DecodeString(kf.Nonce)
	sealed, err3 := base64.StdEncoding.DecodeString(kf.Sealed)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, errors.New("key file is damaged")
	}
	aead, err := keyAEAD(passphrase, salt, kf.Iterations)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("key file is damaged")
	}
	seed, err := aead.Open(nil, nonce, sealed, []byte(keyFileType))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("wrong passphrase, or the key file is damaged")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ---- Manifests ----

// BuildManifest lists the named files in dir.
func BuildManifest(dir, version string, names []string, now time.Time) ([]byte, error) {
	m := Manifest{Schema: 1, Product: Product, Version: strings.TrimPrefix(version, "v"), Published: now.UTC().Truncate(time.Second)}
	if _, err := ParseVersion(m.Version); err != nil {
		return nil, err
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := os.ReadFile(dir + string(os.PathSeparator) + n)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		m.Files = append(m.Files, File{Name: n, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	out, err := json.MarshalIndent(m, "", "  ")
	return append(out, '\n'), err
}

// Sign returns the detached signature for manifest bytes.
func Sign(priv ed25519.PrivateKey, manifest []byte) ([]byte, error) {
	if _, err := ParseManifest(manifest); err != nil {
		return nil, err
	}
	sig := Signature{KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(signContext), manifest...)))}
	out, err := json.MarshalIndent(sig, "", "  ")
	return append(out, '\n'), err
}

// ParseManifest parses a manifest without checking any signature.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != 1 || m.Product != Product {
		return nil, errors.New("manifest is not a Lanternfish Gate release")
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	for _, f := range m.Files {
		if f.Name == "" || strings.ContainsAny(f.Name, `/\`) || len(f.SHA256) != 64 || f.Size < 0 {
			return nil, errors.New("manifest has a malformed file entry")
		}
	}
	return &m, nil
}

// Verify checks a manifest's signature against the trusted keys and returns
// the manifest and the signing key's comment.
func Verify(manifest, signature []byte, keys []PublicKey) (*Manifest, string, error) {
	var sig Signature
	if err := json.Unmarshal(signature, &sig); err != nil {
		return nil, "", errors.New("signature file is malformed")
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, "", errors.New("signature file is malformed")
	}
	for _, k := range keys {
		if KeyID(k.Key) == sig.KeyID && ed25519.Verify(k.Key, append([]byte(signContext), manifest...), raw) {
			m, err := ParseManifest(manifest)
			if err != nil {
				return nil, "", err
			}
			return m, k.Comment, nil
		}
	}
	return nil, "", fmt.Errorf("not signed by a trusted release key (signed by key %s)", sig.KeyID)
}

// File returns the manifest's entry for name.
func (m *Manifest) File(name string) (File, bool) {
	for _, f := range m.Files {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// Check reports whether data is the named file.
func (f File) Check(data []byte) error {
	sum := sha256.Sum256(data)
	if int64(len(data)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return fmt.Errorf("%s does not match the signed manifest", f.Name)
	}
	return nil
}

// ArchiveName is the Gate archive for a version and platform.
func ArchiveName(version, goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("lanternfish-gate_%s_%s_%s%s", strings.TrimPrefix(version, "v"), goos, goarch, ext)
}

// ---- Versions ----

// Version is a semantic version: major.minor.patch[-prerelease].
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q is not major.minor.patch", s)
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("version %q is not major.minor.patch", s)
		}
		n[i] = v
	}
	for _, c := range pre {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.') {
			return Version{}, fmt.Errorf("version %q has a malformed pre-release part", s)
		}
	}
	return Version{n[0], n[1], n[2], pre}, nil
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release;
// pre-release labels compare dot-separated, numerically where both are numbers.
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d != 0 {
			return sign(d)
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	a, b := strings.Split(v.Pre, "."), strings.Split(o.Pre, ".")
	for i := 0; i < len(a) && i < len(b); i++ {
		x, errx := strconv.Atoi(a[i])
		y, erry := strconv.Atoi(b[i])
		switch {
		case errx == nil && erry == nil && x != y:
			return sign(x - y)
		case errx != nil || erry != nil:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(a) - len(b))
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	}
	return 0
}

// AutoAllowed reports whether policy ("off", "patch", "minor", "all") lets
// an automatic update go from cur to next. Pre-releases are never automatic.
func AutoAllowed(policy string, cur, next Version) bool {
	if next.Pre != "" || next.Compare(cur) <= 0 {
		return false
	}
	switch policy {
	case "all":
		return true
	case "minor":
		return next.Major == cur.Major
	case "patch":
		return next.Major == cur.Major && next.Minor == cur.Minor
	}
	return false
}
