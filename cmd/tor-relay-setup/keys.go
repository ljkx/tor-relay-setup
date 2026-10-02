package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/tui"
)

// keysRequest is what `keys` was asked for.
type keysRequest struct {
	Action       string // status | offline | renew
	Instance     string
	RemoveMaster bool   // offline: remove the master key after a verified copy
	Master       string // renew: directory holding the (unencrypted) master key
	From         string // renew: directory with an uploaded signing key and certificate
	Lifetime     string // renew --master: SigningKeyLifetime
	In           io.Reader
	Out          io.Writer
}

// keysCmd runs `tor-relay-setup keys status|offline|renew`.
func keysCmd(h host.Host, req keysRequest) error {
	inst, err := relay.Named(req.Instance)
	if err != nil {
		return err
	}
	if req.Instance == "" {
		// Like status: the default relay, else the first one found.
		if found, _ := relay.Discover(h); len(found) > 0 {
			if d, ok := relay.Find(found, relay.DefaultInstanceName); ok {
				inst = d
			} else {
				inst = found[0]
			}
		}
	}
	keyDir, offline := tui.KeyDirectory(h, inst)
	st := keys.Inspect(h, keyDir, offline)
	out := req.Out
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf := func(s string) { fmt.Fprintln(out, "  "+s) }

	switch req.Action {
	case "", "status":
		printKeys(out, inst, st)
		if w := st.Warnings(time.Now(), 0); len(w) > 0 {
			for _, line := range w {
				fmt.Fprintln(out, "! "+line)
			}
			return errors.New("the identity keys need attention")
		}
		return nil

	case "offline":
		if !req.RemoveMaster {
			fmt.Fprintln(out, keys.Explain)
			fmt.Fprintln(out)
			summary, err := tui.TakeKeyOffline(ctx, h, inst, keyDir, logf)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "\n"+summary)
			return nil
		}
		digest, err := keys.MasterDigest(h, keyDir)
		if err != nil {
			return err
		}
		if !st.Offline {
			return errors.New("torrc does not set OfflineMasterKey 1 yet; run `tor-relay-setup keys offline` first")
		}
		fmt.Fprintf(out, "This removes %s from %s.\n", keys.MasterSecret, keyDir)
		fmt.Fprintf(out, "Run sha256sum on your offline copy and type its first %d or more hex digits: ", keys.MinConfirm)
		typed, _ := bufio.NewReader(req.In).ReadString('\n')
		if !keys.ConfirmMatches(typed, digest) {
			return errors.New("that does not match the master key on this server; nothing was removed")
		}
		export := tui.LatestKeyExport(h, inst)
		if err := keys.RemoveMaster(h, keyDir, st.Offline, typed, export, time.Now()); err != nil {
			return err
		}
		if h.DryRun() {
			fmt.Fprintln(out, "Dry run: the master key would be removed.")
			return nil
		}
		fmt.Fprintln(out, "Removed the master key from this server.")
		if export != "" {
			fmt.Fprintln(out, "Removed the export "+export+".")
		}
		fmt.Fprintf(out, "Renew the signing key before %s:\n\n%s", st.CertExpires.Format("2006-01-02 15:04 UTC"), keys.RenewSteps(inst.Name, ""))
		return nil

	case "renew":
		var secret, cert []byte
		switch {
		case req.Master != "" && req.From != "":
			return errors.New("use --master or --from, not both")
		case req.Master != "":
			if secret, cert, err = keys.Renew(ctx, h, req.Master, req.Lifetime); err != nil {
				return err
			}
			if h.DryRun() {
				fmt.Fprintln(out, "Dry run: tor --keygen would make a new signing key, installed in "+keyDir+".")
				return nil
			}
		case req.From != "":
			if secret, err = h.ReadFile(path.Join(req.From, keys.SigningSecret)); err != nil {
				return err
			}
			if cert, err = h.ReadFile(path.Join(req.From, keys.SigningCert)); err != nil {
				return err
			}
		default:
			printKeys(out, inst, st)
			fmt.Fprintln(out)
			fmt.Fprint(out, keys.RenewSteps(inst.Name, req.Lifetime))
			return nil
		}
		summary, err := tui.InstallSigningKey(ctx, h, inst, keyDir, secret, cert, logf)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, summary)
		switch {
		case req.From != "":
			fmt.Fprintln(out, "Delete the uploaded copies in "+req.From+" when you are done.")
		case req.Master != "" && path.Clean(req.Master) != path.Clean(keyDir):
			fmt.Fprintln(out, "Take the master key in "+req.Master+" off this server again.")
		}
		return nil
	}
	return fmt.Errorf("unknown keys action %q: use status, offline or renew", req.Action)
}

// printKeys prints the identity key state.
func printKeys(w io.Writer, inst relay.Instance, st keys.State) {
	if !inst.IsDefault() {
		fmt.Fprintf(w, "Instance          %s\n", inst.Name)
	}
	master := "on this server"
	switch {
	case st.MasterOnDisk && st.MasterEncrypted:
		master = "on this server (encrypted)"
	case !st.MasterOnDisk && st.Identity != "":
		master = "offline (not on this server)"
	case !st.MasterOnDisk:
		master = "not generated yet"
	}
	fmt.Fprintf(w, "Identity          %s\n", orNone(st.Identity))
	fmt.Fprintf(w, "Master key        %s\n", master)
	fmt.Fprintf(w, "OfflineMasterKey  %v\n", st.Offline)
	switch {
	case st.CertProblem != "":
		fmt.Fprintf(w, "Signing key       %s\n", st.CertProblem)
	case !st.CertExpires.IsZero():
		left := time.Until(st.CertExpires)
		fmt.Fprintf(w, "Signing key       valid until %s (%d days)\n", st.CertExpires.Format("2006-01-02 15:04 UTC"), int(left.Hours()/24))
	}
	fmt.Fprintf(w, "Key directory     %s\n", st.KeyDir)
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
