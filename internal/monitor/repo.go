package monitor

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// maxKeySize bounds a signing-key download.
const maxKeySize = 1 << 20

// ErrUnexpectedKey means a key file did not hold exactly the pinned key.
var ErrUnexpectedKey = errors.New("unexpected repository signing key")

// Repo is a third-party apt repository whose signing key is pinned by
// fingerprint, the same way internal/torproject pins the Tor Project's.
type Repo struct {
	Name        string // shown in the review, e.g. "Grafana"
	URI         string // deb822 URIs
	Suite       string
	Components  string
	KeyURL      string
	Fingerprint string // primary-key fingerprint, upper-case hex
	KeyringPath string // verified binary keyring, referenced by Signed-By
	SourcesPath string // deb822 source
	Host        string // repository host name, to find duplicate sources
}

// GrafanaRepo is Grafana Labs' OSS apt repository. The key at
// https://apt.grafana.com/gpg.key is the 2023-08-24 rsa3072 key
// "Grafana Labs <engineering@grafana.com>" (expires 2027-08-22); it signs
// dists/stable/InRelease. gpg-full.key additionally carries the revoked
// and expired predecessors, which must not be trusted.
var GrafanaRepo = Repo{
	Name:        "Grafana",
	URI:         "https://apt.grafana.com",
	Suite:       "stable",
	Components:  "main",
	KeyURL:      "https://apt.grafana.com/gpg.key",
	Fingerprint: "B53AE77BADB630A683046005963FA27710458545",
	KeyringPath: "/usr/share/keyrings/grafana-archive-keyring.gpg",
	SourcesPath: "/etc/apt/sources.list.d/grafana.sources",
	Host:        "apt.grafana.com",
}

// CaddyRepo is Caddy's official stable repository on Cloudsmith, used only
// where the distribution has no caddy package (Ubuntu 22.04). The primary
// key "Caddy Web Server <contact@caddyserver.com>" (rsa4096, 2016) signs
// InRelease with its 2020 signing subkey ABA1F9B8875A6661.
var CaddyRepo = Repo{
	Name:        "Caddy",
	URI:         "https://dl.cloudsmith.io/public/caddy/stable/deb/debian",
	Suite:       "any-version",
	Components:  "main",
	KeyURL:      "https://dl.cloudsmith.io/public/caddy/stable/gpg.key",
	Fingerprint: "65760C51EDEA2017CEA2CA15155B6D79CA56EA34",
	KeyringPath: "/usr/share/keyrings/caddy-stable-archive-keyring.gpg",
	SourcesPath: "/etc/apt/sources.list.d/caddy-stable.sources",
	Host:        "dl.cloudsmith.io/public/caddy",
}

// Sources is the deb822 apt source, restricted to the verified keyring.
func (r Repo) Sources() []byte {
	return fmt.Appendf(nil, "# Written by tor-relay-setup monitor install (%s, key %s)\nTypes: deb\nURIs: %s\nSuites: %s\nComponents: %s\nSigned-By: %s\n",
		r.Name, r.Fingerprint, r.URI, r.Suite, r.Components, r.KeyringPath)
}

// VerifyKey checks that armored holds exactly one OpenPGP entity whose
// primary key fingerprint is r.Fingerprint and returns it re-serialized in
// binary form, so an extra injected key never reaches the apt keyring.
func (r Repo) VerifyKey(armored []byte) ([]byte, error) {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		return nil, fmt.Errorf("%w (%s): unreadable key file: %w", ErrUnexpectedKey, r.Name, err)
	}
	found := make([]string, 0, len(entities))
	for _, e := range entities {
		found = append(found, strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)))
	}
	if len(entities) != 1 || found[0] != r.Fingerprint {
		return nil, fmt.Errorf("%w (%s): found [%s], expected %s", ErrUnexpectedKey, r.Name, strings.Join(found, " "), r.Fingerprint)
	}
	var out bytes.Buffer
	if err := entities[0].Serialize(&out); err != nil {
		return nil, fmt.Errorf("serialize %s signing key: %w", r.Name, err)
	}
	return out.Bytes(), nil
}

// FetchKey downloads the armored key; pass the result to VerifyKey.
func (r Repo) FetchKey(ctx context.Context, client *http.Client) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.KeyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s (check DNS/network connectivity): %w", r.KeyURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s signing key: %s returned %s", r.Name, r.KeyURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s signing key: %w", r.Name, err)
	}
	if len(data) > maxKeySize {
		return nil, fmt.Errorf("fetch %s signing key: response larger than %d bytes", r.Name, maxKeySize)
	}
	return data, nil
}
