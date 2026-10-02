// Package keys manages a relay's ed25519 identity for offline master keys:
// it parses tor's signing certificate (cert-spec "Ed25519 certificates")
// without the tor-print-ed-signing-cert helper, reports the key directory's
// state, exports the master key for safe keeping, removes it from the server
// only against a verified copy, and renews or installs signing keys.
//
// With OfflineMasterKey 1 a relay holds only ed25519_master_id_public_key,
// ed25519_signing_secret_key and ed25519_signing_cert. The signing key must
// be renewed with `tor --keygen` on the machine that holds the master key
// before the certificate expires (SigningKeyLifetime, default 30 days); tor
// re-reads the new files on SIGHUP and within a day of expiry, and exits
// once the certificate has expired. Sources: tor(1) OfflineMasterKey,
// --keygen, KeyDirectory files; support.torproject.org/relays/running/relay-offline-keys/.
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Files in a relay's KeyDirectory (tor(1), FILES). File names, not secrets.
const (
	MasterSecret          = "ed25519_master_id_secret_key"           //nolint:gosec // a file name
	MasterSecretEncrypted = "ed25519_master_id_secret_key_encrypted" //nolint:gosec // a file name
	MasterPublic          = "ed25519_master_id_public_key"
	SigningSecret         = "ed25519_signing_secret_key" //nolint:gosec // a file name
	SigningCert           = "ed25519_signing_cert"
	// RSAIdentity is the legacy RSA identity; it belongs with the master key.
	RSAIdentity = "secret_id_key"
)

// DefaultWarnDays is how close to expiry the signing certificate starts to
// warn.
const DefaultWarnDays = 7

// DefaultLifetime is the SigningKeyLifetime used for renewals: tor's own
// default.
const DefaultLifetime = "30 days"

// tor wraps key files in a 32-byte header "== TYPE: TAG ==", NUL-padded
// (crypto_format.c, crypto_write_tagged_contents_to_file).
const headerLen = 32

const (
	certHeader      = "== ed25519v1-cert: type4 =="
	publicHeader    = "== ed25519v1-public: type0 =="
	signingHeader   = "== ed25519v1-secret: type4 =="
	certTypeSigning = 0x04 // IDENTITY_V_SIGNING
	extSignedWith   = 0x04 // signed-with-ed25519-key
	extAffects      = 0x01 // AFFECTS_VALIDATION flag
)

// Cert is a parsed ed25519 certificate.
type Cert struct {
	Type    byte
	Expires time.Time
	// Key is the certified key (for ed25519_signing_cert, the signing key).
	Key ed25519.PublicKey
	// Signer is the key from the signed-with-ed25519-key extension (the
	// master identity key); nil when the certificate does not carry it.
	Signer ed25519.PublicKey
	// Signed reports whether Signer's signature over the certificate checks out.
	Signed bool
}

// unwrap strips tor's tagged-file header when it matches want.
func unwrap(data []byte, want string) ([]byte, error) {
	if len(data) < headerLen {
		return nil, errors.New("file too short for a tor key header")
	}
	head := string(bytes.TrimRight(data[:headerLen], "\x00"))
	if head != want {
		return nil, fmt.Errorf("unexpected header %q, want %q", head, want)
	}
	return data[headerLen:], nil
}

// ParseCert parses an ed25519_signing_cert file (or a bare certificate):
// VERSION 01, CERT_TYPE, EXPIRATION_DATE in hours since the epoch,
// CERT_KEY_TYPE, CERTIFIED_KEY (32 bytes), N_EXTENSIONS, the extensions
// (ExtLen 2 bytes, ExtType, ExtFlags, ExtData) and a 64-byte SIGNATURE over
// everything before it.
func ParseCert(data []byte) (Cert, error) {
	if bytes.HasPrefix(data, []byte("== ")) {
		var err error
		if data, err = unwrap(data, certHeader); err != nil {
			return Cert{}, err
		}
	}
	const fixed = 1 + 1 + 4 + 1 + 32 + 1
	if len(data) < fixed+ed25519.SignatureSize {
		return Cert{}, errors.New("certificate too short")
	}
	if data[0] != 1 {
		return Cert{}, fmt.Errorf("unknown certificate version %d", data[0])
	}
	c := Cert{
		Type:    data[1],
		Expires: time.Unix(int64(binary.BigEndian.Uint32(data[2:6]))*3600, 0).UTC(),
		Key:     ed25519.PublicKey(bytes.Clone(data[7:39])),
	}
	n := int(data[39])
	rest := data[fixed:]
	for range n {
		if len(rest) < 4 {
			return Cert{}, errors.New("truncated certificate extension")
		}
		l := int(binary.BigEndian.Uint16(rest[:2]))
		typ, flags := rest[2], rest[3]
		if len(rest) < 4+l {
			return Cert{}, errors.New("truncated certificate extension data")
		}
		ext := rest[4 : 4+l]
		switch {
		case typ == extSignedWith && l == ed25519.PublicKeySize:
			c.Signer = ed25519.PublicKey(bytes.Clone(ext))
		case flags&extAffects != 0:
			return Cert{}, fmt.Errorf("unknown certificate extension %d affects validation", typ)
		}
		rest = rest[4+l:]
	}
	if len(rest) != ed25519.SignatureSize {
		return Cert{}, fmt.Errorf("certificate has %d trailing bytes, want a %d-byte signature", len(rest), ed25519.SignatureSize)
	}
	body := data[:len(data)-ed25519.SignatureSize]
	if c.Signer != nil {
		c.Signed = ed25519.Verify(c.Signer, body, rest)
	}
	return c, nil
}

// ParsePublicKey parses an ed25519_master_id_public_key file.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := unwrap(data, publicHeader)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// validSigningSecret reports whether data looks like an
// ed25519_signing_secret_key file: the header and a 64-byte expanded key.
func validSigningSecret(data []byte) bool {
	raw, err := unwrap(data, signingHeader)
	return err == nil && len(raw) == 64
}

// Identity formats an ed25519 identity the way tor logs it ("Your Tor
// server's identity key ed25519 fingerprint is ...") and relay search shows
// it: unpadded base64.
func Identity(k ed25519.PublicKey) string {
	if len(k) == 0 {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(k)
}

// State is what the key directory says about the relay's identity keys.
type State struct {
	KeyDir string `json:"key_directory"`
	// Offline is torrc's OfflineMasterKey.
	Offline bool `json:"offline_master_key"`
	// MasterOnDisk reports an ed25519_master_id_secret_key (or its
	// encrypted form) in the key directory.
	MasterOnDisk    bool   `json:"master_key_on_disk"`
	MasterEncrypted bool   `json:"master_key_encrypted,omitempty"`
	Identity        string `json:"ed25519_identity,omitempty"`
	// CertExpires is when ed25519_signing_cert expires; zero when unknown.
	CertExpires time.Time `json:"signing_cert_expires,omitzero"`
	// CertProblem explains a missing, unreadable or mismatched certificate.
	CertProblem string `json:"signing_cert_problem,omitempty"`
}

// Inspect reads the key directory through h.
func Inspect(h host.Host, keyDir string, offline bool) State {
	s := State{KeyDir: keyDir, Offline: offline}
	if _, err := h.Stat(path.Join(keyDir, MasterSecret)); err == nil {
		s.MasterOnDisk = true
	}
	if _, err := h.Stat(path.Join(keyDir, MasterSecretEncrypted)); err == nil {
		s.MasterOnDisk, s.MasterEncrypted = true, true
	}
	var master ed25519.PublicKey
	if data, err := h.ReadFile(path.Join(keyDir, MasterPublic)); err == nil {
		if k, err := ParsePublicKey(data); err == nil {
			master = k
			s.Identity = Identity(k)
		}
	}
	data, err := h.ReadFile(path.Join(keyDir, SigningCert))
	if err != nil {
		s.CertProblem = "no " + SigningCert + " yet"
		return s
	}
	c, err := ParseCert(data)
	switch {
	case err != nil:
		s.CertProblem = "cannot parse " + SigningCert + ": " + err.Error()
		return s
	case c.Type != certTypeSigning:
		s.CertProblem = fmt.Sprintf("%s has certificate type %d, want 4", SigningCert, c.Type)
	case c.Signer == nil || !c.Signed:
		s.CertProblem = SigningCert + " is not signed by a master key"
	case master != nil && !c.Signer.Equal(master):
		s.CertProblem = SigningCert + " was signed by a different master key than " + MasterPublic
	}
	if s.Identity == "" {
		s.Identity = Identity(c.Signer)
	}
	s.CertExpires = c.Expires
	return s
}

// Managed reports whether the signing key depends on the operator: the
// master key is offline (or tor is told it is), so tor cannot renew the
// certificate itself.
func (s State) Managed() bool { return s.Offline || (!s.MasterOnDisk && s.Identity != "") }

// Warnings returns what needs attention: a signing certificate that has
// expired or expires within days when tor cannot renew it, and a master key
// that is gone while torrc lacks OfflineMasterKey 1.
func (s State) Warnings(now time.Time, days int) []string {
	if days <= 0 {
		days = DefaultWarnDays
	}
	var w []string
	if !s.MasterOnDisk && !s.Offline && s.Identity != "" {
		w = append(w, "the ed25519 master key is not on this server but torrc lacks OfflineMasterKey 1; set it (tor-relay-setup keys offline) so tor never tries to load or create one")
	}
	if !s.Managed() {
		return w
	}
	switch left := s.CertExpires.Sub(now); {
	case s.CertProblem != "":
		w = append(w, "signing key: "+s.CertProblem)
	case s.CertExpires.IsZero():
	case left <= 0:
		w = append(w, "the ed25519 signing certificate expired on "+s.CertExpires.Format("2006-01-02 15:04 UTC")+"; tor stops: renew it (tor-relay-setup keys renew)")
	case left <= time.Duration(days)*24*time.Hour:
		w = append(w, fmt.Sprintf("the ed25519 signing certificate expires in %s (%s); renew it with tor-relay-setup keys renew",
			humanLeft(left), s.CertExpires.Format("2006-01-02 15:04 UTC")))
	}
	return w
}

// humanLeft formats a remaining duration coarsely: "3 days", "5 hours".
func humanLeft(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	if h := int(d.Hours()); h >= 2 {
		return fmt.Sprintf("%d hours", h)
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}

// Digest returns the SHA-256 of a file, hex encoded.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// MinConfirm is how many leading hex digits of the master key's SHA-256 the
// operator types to prove their offline copy matches.
const MinConfirm = 12

// ConfirmMatches reports whether typed is a prefix of at least MinConfirm
// hex digits of digest (case and surrounding space ignored).
func ConfirmMatches(typed, digest string) bool {
	typed = strings.ToLower(strings.TrimSpace(typed))
	return len(typed) >= MinConfirm && len(digest) >= len(typed) && strings.HasPrefix(digest, typed)
}
