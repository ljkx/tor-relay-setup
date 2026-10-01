package torproject

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// maxKeySize bounds the signing-key download. The real key is about 50 KiB
// (it carries many third-party certifications).
const maxKeySize = 1 << 20

// ErrUnexpectedKey means a key file did not contain exactly the Tor Project
// signing key. Errors from VerifySigningKey wrap it with the fingerprints
// that were found.
var ErrUnexpectedKey = errors.New("unexpected Tor Project signing key")

// VerifySigningKey checks that armored holds exactly one OpenPGP entity whose
// primary key fingerprint is SigningKeyFingerprint and returns that entity
// in binary (dearmored) form, ready to install at KeyringPath.
//
// Exactly one entity is allowed so a key file with an extra injected key
// cannot slip into the apt keyring. The result is re-serialized from the
// parsed entity rather than copied from the input, so it contains only the
// verified public key, its user IDs, subkeys and their signatures.
func VerifySigningKey(armored []byte) ([]byte, error) {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable key file: %w", ErrUnexpectedKey, err)
	}
	found := make([]string, 0, len(entities))
	for _, e := range entities {
		found = append(found, strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)))
	}
	if len(entities) != 1 || found[0] != SigningKeyFingerprint {
		return nil, fmt.Errorf("%w: found [%s], expected %s",
			ErrUnexpectedKey, strings.Join(found, " "), SigningKeyFingerprint)
	}
	var out bytes.Buffer
	if err := entities[0].Serialize(&out); err != nil {
		return nil, fmt.Errorf("serialize Tor Project signing key: %w", err)
	}
	return out.Bytes(), nil
}

// FetchSigningKey downloads the armored signing key from KeyURL. It does not
// verify it; pass the result to VerifySigningKey. A nil client means
// http.DefaultClient.
func FetchSigningKey(ctx context.Context, client *http.Client) ([]byte, error) {
	resp, err := get(ctx, client, KeyURL())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch Tor Project signing key: %s returned %s", KeyURL(), resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch Tor Project signing key: %w", err)
	}
	if len(data) > maxKeySize {
		return nil, fmt.Errorf("fetch Tor Project signing key: response larger than %d bytes", maxKeySize)
	}
	return data, nil
}

// codenameRE matches distribution codenames such as "bookworm" or "noble".
var codenameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// SuiteAvailable reports whether the repository publishes a suite for
// codename, by requesting its Release file. A 404 means the release is not
// (yet) supported and returns false with no error; any other status or a
// transport failure is an error. A nil client means http.DefaultClient.
func SuiteAvailable(ctx context.Context, client *http.Client, codename string) (bool, error) {
	if !codenameRE.MatchString(codename) {
		return false, fmt.Errorf("invalid distribution codename %q", codename)
	}
	url := RepoURL + "/dists/" + codename + "/Release"
	resp, err := get(ctx, client, url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused; the content is unused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("check Tor Project suite %q: %s returned %s", codename, url, resp.Status)
	}
}

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s (check DNS/network connectivity): %w", url, err)
	}
	return resp, nil
}
