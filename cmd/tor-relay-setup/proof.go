package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/proof"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// proofRequest is what `proof` was asked for.
type proofRequest struct {
	Instance string
	All      bool
	Check    bool
	HTTP     *http.Client // tests; nil uses the default client
}

// proofCmd prints the CIISS proof files to publish for the selected relays,
// and with --check fetches the published copies over HTTPS.
func proofCmd(h host.Host, req proofRequest, out io.Writer) error {
	configs, _ := relay.DiscoverConfigs(h)
	var chosen []relay.InstanceConfig
	for _, inst := range statusInstances(h, statusRequest{Instance: req.Instance, All: req.All}) {
		for _, c := range configs {
			if c.Name == inst.Name {
				chosen = append(chosen, c)
			}
		}
	}
	if len(chosen) == 0 {
		return errors.New("no relay is configured here")
	}
	sites := proof.Sites(proof.Local(h, chosen))
	if len(sites) == 0 {
		fmt.Fprintln(out, "Nothing to prove: bridges are never listed in proof files.")
		return nil
	}
	failed := false
	for i, s := range sites {
		if i > 0 {
			fmt.Fprintln(out)
		}
		domain := s.Domain
		if domain == "" {
			domain = "YOUR-DOMAIN"
		}
		fmt.Fprintf(out, "Relays: %s\n", strings.Join(s.Relays, ", "))
		for _, a := range proof.Advice(s) {
			fmt.Fprintln(out, "! "+a)
		}
		var results map[string]proof.Result
		if req.Check && s.Domain != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			results = map[string]proof.Result{}
			for _, r := range proof.CheckSite(ctx, proof.Client(req.HTTP), s) {
				results[r.URL] = r
			}
			cancel()
		}
		for _, f := range s.Files {
			label := "CIISS v3, proof:uri-familyid-ed25519"
			if f.Kind == proof.Fingerprints {
				label = "legacy CIISS v2, proof:uri-rsa"
			}
			fmt.Fprintf(out, "\n== https://%s%s  (%s)\n", domain, f.Kind.Path(), label)
			fmt.Fprint(out, string(f.Content))
			if r, ok := results[f.URL]; ok {
				switch {
				case r.Error != "":
					failed = true
					fmt.Fprintf(out, "check: FAILED: %s\n", r.Error)
				case !r.OK:
					failed = true
					fmt.Fprintf(out, "check: published, but missing %s\n", strings.Join(r.Missing, ", "))
				default:
					fmt.Fprintln(out, "check: ok, lists every entry")
				}
				for _, n := range r.Notes {
					fmt.Fprintln(out, "check: note: "+n)
				}
			}
		}
	}
	if req.Check {
		fmt.Fprintln(out, "\nThe files must be served over HTTPS with a trusted certificate, as text/plain, without a redirect to another domain.")
	}
	if failed {
		return errors.New("a published proof file is missing or out of date")
	}
	return nil
}
