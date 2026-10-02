package tui

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
)

// keysView guides an operator through offline master keys: take the master
// key off the server (export, verify the offline copy, remove), renew the
// signing key before it expires, and install a signing key made elsewhere.
type keysView struct {
	back   *console
	cursor int
	form   *huh.Form
	mode   string // "", remove, renew, install, help
	typed  string
	dir    string
	life   string
	// clock dates the signing key's remaining validity (tests pin it).
	clock func() time.Time
}

func newKeysView(back *console) *keysView {
	return &keysView{back: back, life: keys.DefaultLifetime, dir: uploadDir(back.selected()), clock: time.Now}
}

func (k *keysView) now() time.Time { return k.clock() }

// uploadDir is where RenewSteps tells the operator to upload signing keys.
func uploadDir(inst relay.Instance) string {
	if inst.OrDefault().IsDefault() {
		return "/root/tor-signing"
	}
	return "/root/tor-signing-" + inst.Name
}

var keysActions = []struct{ key, label, desc string }{
	{"o", "Take the master key offline", "Set OfflineMasterKey 1 and export the key for download"},
	{"x", "Remove the master key from this server", "After you verified your offline copy"},
	{"r", "Renew the signing key here", "Needs the master key on this server (unencrypted)"},
	{"i", "Install an uploaded signing key", "Made with tor --keygen on your offline machine"},
	{"h", "How to renew offline", "Commands for the machine that holds the master key"},
}

// state returns the key directory's state for the selected relay.
func (k *keysView) state(a *App) keys.State {
	if st := k.back.report.Keys; st != nil {
		return *st
	}
	inst := k.back.selected()
	offline := false
	if data, err := a.opt.Host.ReadFile(inst.TorrcPath); err == nil {
		offline = relay.ParseDocument(data).OfflineMasterKey()
	}
	return keys.Inspect(a.opt.Host, inst.KeyDir, offline)
}

func (k *keysView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if k.form != nil {
		m, cmd := k.form.Update(msg)
		if f, ok := m.(*huh.Form); ok {
			k.form = f
		}
		switch k.form.State {
		case huh.StateCompleted:
			k.form = nil
			return k.run(a)
		case huh.StateAborted:
			k.form, k.mode = nil, ""
		}
		return k, cmd
	}
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc", "q", "backspace":
			if k.mode == "help" {
				k.mode = ""
				return k, nil
			}
			return k.back, k.back.refresh(a)
		case "up", "k":
			k.cursor = (k.cursor - 1 + len(keysActions)) % len(keysActions)
		case "down", "j", "tab":
			k.cursor = (k.cursor + 1) % len(keysActions)
		case "enter":
			return k.start(a, keysActions[k.cursor].key)
		default:
			for _, act := range keysActions {
				if key.String() == act.key {
					return k.start(a, act.key)
				}
			}
		}
	}
	return k, nil
}

func (k *keysView) start(a *App, action string) (screen, tea.Cmd) {
	st := k.state(a)
	inst := k.back.selected()
	keyDir := st.KeyDir
	switch action {
	case "o":
		if !st.MasterOnDisk {
			return k, toast("The master key is not on this server: it is already offline.")
		}
		back := k.back
		question := "Set OfflineMasterKey 1 for " + inst.Unit + " and copy the master key to " + keys.ExportRoot + " for download? Nothing is removed yet."
		return newConfirmView(k, question, func() (screen, tea.Cmd) {
			return newTask(a, back, "Take the master key offline"+instanceTitle(inst), offlineTask(inst, keyDir))
		}), nil
	case "x":
		switch {
		case !st.MasterOnDisk:
			return k, toast("The master key is not on this server.")
		case !st.Offline:
			return k, toast("Take the master key offline first (o): it sets OfflineMasterKey 1 and exports the key.")
		}
		k.mode, k.typed = "remove", ""
		digest, _ := keys.MasterDigest(a.opt.Host, keyDir)
		k.form = huh.NewForm(huh.NewGroup(
			huh.NewNote().Title("Remove the master key").Description(fmt.Sprintf(
				"On your offline machine run sha256sum on your copy of %s. Type its first %d or more hex digits to prove the copy is intact. Without that copy this relay's identity cannot be renewed.",
				keys.MasterSecret, keys.MinConfirm)),
			huh.NewInput().Title("SHA-256 of your offline copy").Value(&k.typed).Validate(func(s string) error {
				if !keys.ConfirmMatches(s, digest) {
					return fmt.Errorf("does not match the master key on this server (type at least %d hex digits)", keys.MinConfirm)
				}
				return nil
			}),
		)).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	case "r":
		if !st.MasterOnDisk {
			k.mode = "help"
			return k, toast("The master key is offline: renew on the machine that holds it (instructions below), then install the upload (i).")
		}
		if st.MasterEncrypted {
			k.mode = "help"
			return k, toast("The master key is encrypted: renew on the machine that holds it, where tor can ask for the passphrase.")
		}
		k.mode = "renew"
		k.form = huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Signing key lifetime").Description("tor --keygen --SigningKeyLifetime; tor's default is 30 days.").
				Value(&k.life).Validate(func(s string) error {
				if !keys.ValidLifetime(strings.TrimSpace(s)) {
					return errors.New("a number of days, weeks or months, e.g. 30 days")
				}
				return nil
			}),
		)).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	case "i":
		k.mode = "install"
		k.form = huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Directory with " + keys.SigningSecret + " and " + keys.SigningCert).Value(&k.dir).
				Validate(func(s string) error {
					for _, name := range []string{keys.SigningSecret, keys.SigningCert} {
						if _, err := a.opt.Host.Stat(path.Join(strings.TrimSpace(s), name)); err != nil {
							return errors.New("no " + name + " there")
						}
					}
					return nil
				}),
		)).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	case "h":
		k.mode = "help"
		return k, nil
	}
	if k.form != nil {
		return k, k.form.Init()
	}
	return k, nil
}

func (k *keysView) run(a *App) (screen, tea.Cmd) {
	back := k.back
	inst := back.selected()
	st := k.state(a)
	keyDir := st.KeyDir
	switch k.mode {
	case "remove":
		typed := k.typed
		return newTask(a, back, "Remove the master key"+instanceTitle(inst), func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			export := latestExport(h, inst)
			if err := keys.RemoveMaster(h, keyDir, st.Offline, typed, export, time.Now()); err != nil {
				return "", err
			}
			if h.DryRun() {
				return "Dry run: " + keys.MasterSecret + " would be removed from " + keyDir + ".", nil
			}
			summary := "The master key is gone from this server; your offline copy is now the only one in use.\n" +
				"Renew the signing key before " + st.CertExpires.Format("2006-01-02") + ": Identity keys → How to renew offline."
			if export != "" {
				summary += "\nRemoved the export " + export + " as well."
			}
			return summary, nil
		})
	case "renew":
		life := strings.TrimSpace(k.life)
		return newTask(a, back, "Renew the signing key"+instanceTitle(inst), func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			progress(20, "tor --keygen")
			secret, cert, err := keys.Renew(ctx, h, keyDir, life)
			if err != nil {
				return "", err
			}
			if h.DryRun() {
				return "Dry run: tor --keygen would make a new signing key valid for " + life + ".", nil
			}
			return installSigning(ctx, h, inst, keyDir, secret, cert, out)
		})
	case "install":
		dir := strings.TrimSpace(k.dir)
		return newTask(a, back, "Install the signing key"+instanceTitle(inst), func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			secret, err := h.ReadFile(path.Join(dir, keys.SigningSecret))
			if err != nil {
				return "", err
			}
			cert, err := h.ReadFile(path.Join(dir, keys.SigningCert))
			if err != nil {
				return "", err
			}
			summary, err := installSigning(ctx, h, inst, keyDir, secret, cert, out)
			if err == nil {
				summary += "\nDelete the uploaded copies in " + dir + " when you are done."
			}
			return summary, err
		})
	}
	return k, nil
}

// The offline key steps for `tor-relay-setup keys`, shared with the console.

// TakeKeyOffline sets OfflineMasterKey 1 for inst (verified with tor, then
// reloaded) and exports the master key from keyDir for download; it removes
// nothing. The summary tells the operator what to do next.
func TakeKeyOffline(ctx context.Context, h host.Host, inst relay.Instance, keyDir string, out func(string)) (string, error) {
	return offlineTask(inst, keyDir)(ctx, h, out, func(float64, string) {})
}

// InstallSigningKey checks a signing key and certificate against inst's
// master key, installs them in keyDir for tor, and reloads tor.
func InstallSigningKey(ctx context.Context, h host.Host, inst relay.Instance, keyDir string, secret, cert []byte, out func(string)) (string, error) {
	return installSigning(ctx, h, inst, keyDir, secret, cert, out)
}

// LatestKeyExport returns the newest master key export of inst, or "".
func LatestKeyExport(h host.Host, inst relay.Instance) string { return latestExport(h, inst) }

// KeyDirectory returns inst's key directory (KeyDirectory, else
// DataDirectory/keys) and whether its torrc sets OfflineMasterKey 1.
func KeyDirectory(h host.Host, inst relay.Instance) (dir string, offline bool) {
	inst = inst.OrDefault()
	data, err := h.ReadFile(inst.TorrcPath)
	if err != nil {
		return inst.KeyDir, false
	}
	doc := relay.ParseDocument(data)
	if kd, ok := doc.Get("KeyDirectory"); ok && relay.Unquote(strings.TrimSpace(kd)) != "" {
		return relay.Unquote(strings.TrimSpace(kd)), doc.OfflineMasterKey()
	}
	return strings.TrimRight(doc.DataDirectoryOr(inst.DataDir), "/") + "/keys", doc.OfflineMasterKey()
}

// offlineTask sets OfflineMasterKey 1 and exports the master key.
func offlineTask(inst relay.Instance, keyDir string) taskFunc {
	inst = inst.OrDefault()
	return func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
		data, err := h.ReadFile(inst.TorrcPath)
		if err != nil {
			return "", err
		}
		doc := relay.ParseDocument(data)
		doc.SetOfflineMasterKey(true)
		progress(20, "OfflineMasterKey 1")
		if err := writeTorrc(ctx, h, inst, doc.Bytes(), false, out); err != nil {
			return "", err
		}
		progress(60, "exporting the master key")
		ex, err := keys.ExportMaster(h, keyDir, keys.ExportDir(inst.Name, time.Now()))
		if err != nil {
			return "", err
		}
		for _, f := range ex.Files {
			out("copied " + f)
		}
		return "OfflineMasterKey 1 is set. The master key is still on this server until you remove it.\n\n" + keys.DownloadSteps(ex, inst.Name) +
			"\n   (In the console: Identity keys → Remove the master key.)", nil
	}
}

// installSigning installs a signing key for inst and reloads tor, which
// re-reads the key files on SIGHUP.
func installSigning(ctx context.Context, h host.Host, inst relay.Instance, keyDir string, secret, cert []byte, out func(string)) (string, error) {
	inst = inst.OrDefault()
	c, err := keys.InstallSigning(h, keyDir, inst.User, secret, cert, time.Now())
	if err != nil {
		return "", err
	}
	out("installed " + keys.SigningSecret + " and " + keys.SigningCert + " for " + inst.User)
	out("systemctl reload " + inst.Unit)
	if err := (service.Tor{Host: h, Unit: inst.Unit}).Reload(ctx); err != nil {
		return "", err
	}
	if h.DryRun() {
		return "Dry run: the signing key would be installed.", nil
	}
	return "New signing key valid until " + c.Expires.Format("2006-01-02 15:04 UTC") + ".", nil
}

// latestExport finds the newest master key export of inst under /root.
func latestExport(h host.Host, inst relay.Instance) string {
	pattern := keys.ExportRoot + "/tor-master-key-2*"
	if !inst.OrDefault().IsDefault() {
		pattern = keys.ExportRoot + "/tor-master-key-" + inst.Name + "-2*"
	}
	matches, _ := h.Glob(pattern + "/" + keys.MasterPublic)
	if len(matches) == 0 {
		return ""
	}
	slices.Sort(matches)
	return path.Dir(matches[len(matches)-1])
}

func (k *keysView) view(a *App) string {
	t := a.theme
	w := a.contentWidth()
	title := t.Title.Render(" Identity keys") + t.Subtle.Render(instanceTitle(k.back.selected())+" · ed25519 master and signing keys")
	if k.form != nil {
		return title + "\n\n" + panel(t, "", k.form.View(), clamp(w, 40, 100), true)
	}
	st := k.state(a)
	master := "on this server"
	switch {
	case st.MasterOnDisk && st.MasterEncrypted:
		master = "on this server (encrypted)"
	case !st.MasterOnDisk && st.Identity != "":
		master = statusIcon(t, true, false) + " offline (not on this server)"
	case !st.MasterOnDisk:
		master = t.Subtle.Render("not generated yet")
	}
	rows := [][2]string{
		{"Identity", st.Identity},
		{"Master key", master},
		{"OfflineMasterKey", yesNo(st.Offline)},
		{"Signing key", signingKeyLine(t, st, k.now())},
		{"Key directory", st.KeyDir},
	}
	var menu strings.Builder
	for i, act := range keysActions {
		line := " " + t.Key.Render(act.key) + "  " + act.label
		if i == k.cursor {
			line = t.Selected.Render(" "+act.key+"  "+act.label) + "\n" + t.Subtle.Render("    "+act.desc)
		}
		menu.WriteString(line + "\n")
	}
	body := panel(t, "Status", kv(t, rows), w, false) + "\n" +
		panel(t, "Actions", strings.TrimRight(menu.String(), "\n"), w, true)
	if k.mode == "help" {
		body += "\n" + panel(t, "Renew on the machine that holds the master key", keys.RenewSteps(k.back.selected().Name, ""), w, true)
	} else {
		body += "\n" + panel(t, "How offline keys work", t.Subtle.Render(keys.Explain), w, false)
	}
	return title + "\n\n" + body
}

func (k *keysView) keys(a *App) []string {
	if k.form != nil {
		return []string{"enter", "next", "esc", "cancel"}
	}
	return []string{"↑/↓", "select", "enter", "run", "esc", "back"}
}

// signingKeyLine summarises the signing certificate's validity.
func signingKeyLine(t Theme, st keys.State, now time.Time) string {
	switch left := st.CertExpires.Sub(now); {
	case st.CertProblem != "":
		return statusIcon(t, false, true) + " " + st.CertProblem
	case st.CertExpires.IsZero():
		return t.Subtle.Render("unknown")
	case left <= 0:
		return statusIcon(t, false, false) + " expired " + st.CertExpires.Format("2006-01-02")
	case left <= keys.DefaultWarnDays*24*time.Hour && st.Managed():
		return statusIcon(t, false, true) + fmt.Sprintf(" until %s (%d days left)", st.CertExpires.Format("2006-01-02"), int(left.Hours()/24))
	default:
		return statusIcon(t, true, false) + fmt.Sprintf(" until %s (%d days)", st.CertExpires.Format("2006-01-02"), int(left.Hours()/24))
	}
}
