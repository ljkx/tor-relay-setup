package keys

import (
	"fmt"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Explain describes the offline master key model in a few lines.
const Explain = `A relay's identity is its ed25519 master key. With an offline master key,
that key lives on a machine you control (an encrypted USB stick, an offline
laptop) and the relay only holds a medium-term signing key and certificate,
signed by the master key and valid for SigningKeyLifetime (default 30 days).
If the server is compromised, the attacker gets a signing key that expires,
not your relay's identity. The price: you renew the signing key before it
expires, or the relay stops.`

// flag returns " --instance NAME" for a named instance, else "".
func instanceFlag(instance string) string {
	if instance == "" || instance == "default" {
		return ""
	}
	return " --instance " + instance
}

// offlineDir is the suggested directory on the offline machine.
func offlineDir(instance string) string {
	if instance == "" || instance == "default" {
		return "~/tor-master"
	}
	return "~/tor-master-" + instance
}

// DownloadSteps tells the operator how to fetch an export and prove the
// offline copy matches, before the master key is removed from the server.
func DownloadSteps(ex Export, instance string) string {
	dir := offlineDir(instance)
	var b strings.Builder
	fmt.Fprintf(&b, "1. On the machine that will keep the master key (not this server):\n\n")
	fmt.Fprintf(&b, "     mkdir -p %s/keys && chmod 700 %s %s/keys\n", dir, dir, dir)
	fmt.Fprintf(&b, "     scp 'root@THIS-SERVER:%s/*' %s/keys/\n", ex.Dir, dir)
	fmt.Fprintf(&b, "     sha256sum %s/keys/ed25519_master_id_secret_key*\n\n", dir)
	fmt.Fprintf(&b, "   The SHA-256 must start with %s. Keep a second copy too (an encrypted\n", short(ex.Digest))
	fmt.Fprintf(&b, "   USB stick): without the master key the relay's identity cannot be renewed.\n\n")
	fmt.Fprintf(&b, "2. Then remove the master key from this server:\n\n")
	fmt.Fprintf(&b, "     sudo tor-relay-setup keys offline --remove-master%s\n\n", instanceFlag(instance))
	fmt.Fprintf(&b, "   It asks for the first %d hex digits of that SHA-256, and deletes\n", MinConfirm)
	fmt.Fprintf(&b, "   %s from the key directory and %s.\n", MasterSecret, ex.Dir)
	return b.String()
}

// RenewSteps tells the operator how to renew the signing key on the machine
// that holds the master key and install it on the relay.
func RenewSteps(instance, lifetime string) string {
	if lifetime == "" {
		lifetime = DefaultLifetime
	}
	dir := offlineDir(instance)
	upload := "/root/tor-signing"
	if instance != "" && instance != "default" {
		upload += "-" + instance
	}
	var b strings.Builder
	fmt.Fprintf(&b, "On the machine that holds the master key (%s/keys):\n\n", dir)
	fmt.Fprintf(&b, "  tor --keygen --DataDirectory %s --SigningKeyLifetime %s\n", dir, host.Quote(lifetime))
	fmt.Fprintf(&b, "  ssh root@THIS-SERVER 'mkdir -m 700 -p %s'\n", upload)
	fmt.Fprintf(&b, "  scp %s/keys/%s %s/keys/%s root@THIS-SERVER:%s/\n\n", dir, SigningSecret, dir, SigningCert, upload)
	fmt.Fprintf(&b, "Then on this server (checks the certificate, installs it for tor, reloads):\n\n")
	fmt.Fprintf(&b, "  sudo tor-relay-setup keys renew --from %s%s\n\n", upload, instanceFlag(instance))
	fmt.Fprintf(&b, "If the master key is temporarily on this server instead (unencrypted):\n\n")
	fmt.Fprintf(&b, "  sudo tor-relay-setup keys renew --master DIR%s\n", instanceFlag(instance))
	return b.String()
}

func short(digest string) string {
	if len(digest) > MinConfirm {
		return digest[:MinConfirm]
	}
	return digest
}
