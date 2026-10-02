package keys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// ExportRoot is where Export puts the copy of the master key for the
// operator to download: root's home, outside the tor data directory.
const ExportRoot = "/root"

// ExportDir names the export directory for an instance at now.
func ExportDir(instance string, now time.Time) string {
	name := "tor-master-key-"
	if instance != "" && instance != "default" {
		name += instance + "-"
	}
	return path.Join(ExportRoot, name+now.UTC().Format("20060102T150405Z"))
}

// Export is a copy of a relay's identity keys.
type Export struct {
	Dir    string
	Files  []string // copied files, full paths
	Digest string   // SHA-256 of the master secret key file
}

// ExportMaster copies the identity keys from keyDir into dir (mode 0700, files
// 0600, owned by root): the ed25519 master secret key (or its encrypted
// form), the master public key, and the RSA secret_id_key that belongs with
// it. Every copy is read back and compared before ExportMaster reports success.
// It never touches keyDir. On a dry-run host nothing is written and Digest
// is the digest of the live key.
func ExportMaster(h host.Host, keyDir, dir string) (Export, error) {
	secretName := MasterSecret
	secret, err := h.ReadFile(path.Join(keyDir, MasterSecret))
	if errors.Is(err, fs.ErrNotExist) {
		secretName = MasterSecretEncrypted
		secret, err = h.ReadFile(path.Join(keyDir, MasterSecretEncrypted))
	}
	if err != nil {
		return Export{}, fmt.Errorf("no ed25519 master key in %s to export (is it already offline?): %w", keyDir, err)
	}
	ex := Export{Dir: dir, Digest: Digest(secret)}
	if err := h.MkdirAll(dir, 0o700, ""); err != nil {
		return Export{}, err
	}
	for _, name := range []string{secretName, MasterPublic, RSAIdentity} {
		src := path.Join(keyDir, name)
		data, err := h.ReadFile(src)
		if err != nil {
			if name == RSAIdentity && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return Export{}, fmt.Errorf("read %s: %w", src, err)
		}
		dst := path.Join(dir, name)
		if _, err := h.WriteFile(dst, data, host.FileOptions{Mode: 0o600}); err != nil {
			return Export{}, err
		}
		if !h.DryRun() {
			back, err := h.ReadFile(dst)
			if err != nil || Digest(back) != Digest(data) {
				return Export{}, fmt.Errorf("the copy %s does not match %s; nothing was removed", dst, src)
			}
		}
		ex.Files = append(ex.Files, dst)
	}
	return ex, nil
}

// MasterDigest returns the SHA-256 of the master secret key in keyDir.
func MasterDigest(h host.Host, keyDir string) (string, error) {
	for _, name := range []string{MasterSecret, MasterSecretEncrypted} {
		if data, err := h.ReadFile(path.Join(keyDir, name)); err == nil {
			return Digest(data), nil
		}
	}
	return "", fmt.Errorf("no ed25519 master key in %s", keyDir)
}

// minCertLeft is how long the signing certificate must still be valid when
// the master key leaves the server: enough to fetch the master key and
// renew calmly.
const minCertLeft = 24 * time.Hour

// RemoveMaster deletes the ed25519 master secret key from keyDir, and the
// export directory made by ExportMaster (if exportDir is not empty), once all of
// these hold:
//   - torrc sets OfflineMasterKey 1 (offline), so tor never creates a new
//     identity in its place;
//   - the signing certificate was signed by this relay's master key and is
//     valid for at least another day;
//   - typed is a prefix (MinConfirm hex digits or more) of the SHA-256 of
//     the master key, as `sha256sum ed25519_master_id_secret_key` prints it
//     for the operator's offline copy. That proves the copy exists and is
//     intact; this is never the only copy that gets deleted.
//
// The RSA identity key stays: tor needs it to run.
func RemoveMaster(h host.Host, keyDir string, offline bool, typed, exportDir string, now time.Time) error {
	if !offline {
		return errors.New("torrc does not set OfflineMasterKey 1 yet; set it first (tor would otherwise try to create a new identity)")
	}
	digest, err := MasterDigest(h, keyDir)
	if err != nil {
		return err
	}
	st := Inspect(h, keyDir, offline)
	switch {
	case st.CertProblem != "":
		return errors.New("refusing: " + st.CertProblem)
	case st.CertExpires.Sub(now) < minCertLeft:
		return fmt.Errorf("refusing: the signing certificate expires %s; renew it before taking the master key offline", st.CertExpires.Format("2006-01-02 15:04 UTC"))
	case !ConfirmMatches(typed, digest):
		return fmt.Errorf("refusing: the confirmation does not match the master key's SHA-256 (type at least its first %d hex digits, from sha256sum of your offline copy)", MinConfirm)
	}
	for _, name := range []string{MasterSecret, MasterSecretEncrypted} {
		p := path.Join(keyDir, name)
		if _, err := h.Stat(p); err == nil {
			if err := h.Remove(p); err != nil {
				return err
			}
		}
	}
	if exportDir != "" {
		if _, err := h.Stat(exportDir); err == nil {
			return h.Remove(exportDir)
		}
	}
	return nil
}

var lifetimeRe = regexp.MustCompile(`^[1-9][0-9]{0,3} (days|weeks|months)$`)

// ValidLifetime reports whether s is a SigningKeyLifetime tor accepts, in
// the form "N days|weeks|months".
func ValidLifetime(s string) bool { return lifetimeRe.MatchString(s) }

// Renew makes a new signing key and certificate with tor --keygen from the
// unencrypted master key in masterDir (ed25519_master_id_secret_key and
// ed25519_master_id_public_key, e.g. temporarily copied back to the server).
// tor runs in a private temporary directory with empty torrc files, never
// in the live key directory; the copy is removed afterwards. On a dry-run
// host tor is not run and Renew returns (nil, nil, nil).
func Renew(ctx context.Context, h host.Host, masterDir, lifetime string) (secret, cert []byte, err error) {
	if lifetime == "" {
		lifetime = DefaultLifetime
	}
	if !ValidLifetime(lifetime) {
		return nil, nil, fmt.Errorf("signing key lifetime %q: use N days, weeks or months", lifetime)
	}
	master, err := h.ReadFile(path.Join(masterDir, MasterSecret))
	if err != nil {
		if _, encErr := h.Stat(path.Join(masterDir, MasterSecretEncrypted)); encErr == nil {
			return nil, nil, errors.New("the master key is encrypted: renew on the machine that holds it, where tor --keygen can ask for the passphrase")
		}
		return nil, nil, fmt.Errorf("no master key in %s: %w", masterDir, err)
	}
	public, err := h.ReadFile(path.Join(masterDir, MasterPublic))
	if err != nil {
		return nil, nil, fmt.Errorf("no master public key in %s: %w", masterDir, err)
	}
	work, err := os.MkdirTemp("", "tor-keygen-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(work)
	keyDir := filepath.Join(work, "data", "keys")
	empty := filepath.Join(work, "empty.torrc")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, nil, err
	}
	for p, data := range map[string][]byte{
		filepath.Join(keyDir, MasterSecret): master,
		filepath.Join(keyDir, MasterPublic): public,
		empty:                               nil,
	} {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return nil, nil, err
		}
	}
	cmd := host.Command{
		Name: "tor",
		Args: []string{"--defaults-torrc", empty, "-f", empty, "--keygen", "--no-passphrase",
			"--DataDirectory", filepath.Join(work, "data"), "--SigningKeyLifetime", lifetime},
		Dir:     work,
		Mutates: true,
	}
	if _, err := h.Run(ctx, cmd); err != nil {
		return nil, nil, fmt.Errorf("tor --keygen: %w", err)
	}
	if h.DryRun() {
		return nil, nil, nil
	}
	if secret, err = os.ReadFile(filepath.Join(keyDir, SigningSecret)); err != nil {
		return nil, nil, fmt.Errorf("tor --keygen wrote no %s: %w", SigningSecret, err)
	}
	if cert, err = os.ReadFile(filepath.Join(keyDir, SigningCert)); err != nil {
		return nil, nil, fmt.Errorf("tor --keygen wrote no %s: %w", SigningCert, err)
	}
	return secret, cert, nil
}

// InstallSigning checks a signing key and certificate against the relay and
// installs them in keyDir (mode 0600, owned by owner, previous files backed
// up). The certificate must be a signing certificate signed by the master
// key in keyDir's ed25519_master_id_public_key, and not expired. tor picks
// the new files up on reload (SIGHUP).
func InstallSigning(h host.Host, keyDir, owner string, secret, cert []byte, now time.Time) (Cert, error) {
	c, err := ParseCert(cert)
	if err != nil {
		return Cert{}, fmt.Errorf("%s: %w", SigningCert, err)
	}
	pubData, err := h.ReadFile(path.Join(keyDir, MasterPublic))
	if err != nil {
		return Cert{}, fmt.Errorf("the relay has no %s to check the certificate against: %w", MasterPublic, err)
	}
	master, err := ParsePublicKey(pubData)
	if err != nil {
		return Cert{}, fmt.Errorf("%s: %w", MasterPublic, err)
	}
	switch {
	case c.Type != certTypeSigning:
		return Cert{}, fmt.Errorf("%s has certificate type %d, want a signing certificate (4)", SigningCert, c.Type)
	case !c.Signed || !c.Signer.Equal(master):
		return Cert{}, fmt.Errorf("%s was not signed by this relay's master key (%s); it belongs to another relay", SigningCert, Identity(master))
	case !c.Expires.After(now):
		return Cert{}, fmt.Errorf("%s already expired on %s", SigningCert, c.Expires.Format("2006-01-02 15:04 UTC"))
	case !validSigningSecret(secret):
		return Cert{}, fmt.Errorf("%s is not an ed25519 signing key file", SigningSecret)
	}
	for name, data := range map[string][]byte{SigningSecret: secret, SigningCert: cert} {
		if _, err := h.WriteFile(path.Join(keyDir, name), data, host.FileOptions{Mode: 0o600, Owner: owner, Backup: true}); err != nil {
			return Cert{}, err
		}
	}
	return c, nil
}

// MasterPublicKey reads the relay's master public key, if present.
func MasterPublicKey(h host.Host, keyDir string) (ed25519.PublicKey, error) {
	data, err := h.ReadFile(path.Join(keyDir, MasterPublic))
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}
