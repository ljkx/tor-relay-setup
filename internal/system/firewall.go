package system

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Firewall manager kinds.
const (
	KindUFW       = "ufw"
	KindFirewalld = "firewalld"
	KindNFTables  = "nftables"
	KindNone      = "none"
)

// Firewall.Detail values.
const (
	DetailActive        = "active"
	DetailInactive      = "inactive"
	DetailInstalled     = "installed" // ufw present but its status is unreadable (not root)
	DetailNFTChainFound = "inet filter input chain found"
	DetailNFTNoChain    = "no inet filter input chain"
	DetailNone          = "no supported firewall manager found"
)

// Firewall describes the firewall manager found on the machine.
type Firewall struct {
	Kind   string // KindUFW, KindFirewalld, KindNFTables or KindNone
	Active bool
	Detail string // one of the Detail* constants
}

// DetectFirewall finds the firewall manager the way the installer prefers
// them: ufw, then firewalld, then an nftables "inet filter input" chain. It
// runs only read-only commands.
func DetectFirewall(ctx context.Context, h host.Host) Firewall {
	// PATH lookups for missing programs can be slow (network or WSL mounts
	// in PATH), so resolve all three at once.
	tools := []string{"ufw", "firewall-cmd", "nft"}
	found := make([]bool, len(tools))
	var wg sync.WaitGroup
	for i, name := range tools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.LookPath(name)
			found[i] = err == nil
		}()
	}
	wg.Wait()
	hasUFW, hasFirewalld, hasNFT := found[0], found[1], found[2]

	if hasUFW {
		out, err := probe(ctx, h, "ufw", "status")
		if err != nil {
			return Firewall{Kind: KindUFW, Detail: DetailInstalled}
		}
		first, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(out)), "\n")
		switch {
		case strings.Contains(first, "inactive"):
			return Firewall{Kind: KindUFW, Detail: DetailInactive}
		case strings.Contains(first, "active"):
			return Firewall{Kind: KindUFW, Active: true, Detail: DetailActive}
		}
		return Firewall{Kind: KindUFW, Detail: DetailInstalled}
	}
	if hasFirewalld {
		if _, err := probe(ctx, h, "systemctl", "is-active", "--quiet", "firewalld"); err == nil {
			return Firewall{Kind: KindFirewalld, Active: true, Detail: DetailActive}
		}
		return Firewall{Kind: KindFirewalld, Detail: DetailInactive}
	}
	if hasNFT {
		if _, err := probe(ctx, h, "nft", "list", "chain", "inet", "filter", "input"); err == nil {
			return Firewall{Kind: KindNFTables, Active: true, Detail: DetailNFTChainFound}
		}
		return Firewall{Kind: KindNFTables, Detail: DetailNFTNoChain}
	}
	return Firewall{Kind: KindNone, Detail: DetailNone}
}

// nftComment is the comment tagging the installer's nftables rule.
func nftComment(orPort int) string { return "Tor relay ORPort " + strconv.Itoa(orPort) }

// NFTRuleExists reports whether the "inet filter input" chain already holds
// the installer's ORPort rule, so a rerun does not add a duplicate. It runs
// a read-only command and reports false on any error.
func NFTRuleExists(ctx context.Context, h host.Host, orPort int) bool {
	out, err := probe(ctx, h, "nft", "list", "chain", "inet", "filter", "input")
	return err == nil && strings.Contains(out, `"`+nftComment(orPort)+`"`)
}

// FirewallCommands returns the commands that open TCP orPort for fw; the
// caller runs them in order. All are marked Mutates.
//
//   - ufw: while ufw is inactive, each SSH port is allowed first (so enabling
//     ufw cannot lock the operator out; [22] when sshPorts is empty), then
//     the ORPort, then `ufw --force enable` when enableUFW is set. enableUFW
//     is ignored when ufw is already active.
//   - firewalld: only when active, a permanent port rule plus a reload.
//   - nftables: only when the inet filter input chain exists (callers may
//     skip it when NFTRuleExists reports true).
//   - anything else: no commands.
//
// installUFW means the caller installs ufw (via apt) before running these
// commands; fw is then treated as a freshly installed, inactive ufw.
func FirewallCommands(fw Firewall, orPort int, sshPorts []int, enableUFW, installUFW bool) []host.Command {
	if installUFW {
		fw = Firewall{Kind: KindUFW, Detail: DetailInactive}
	}
	port := strconv.Itoa(orPort) + "/tcp"
	var cmds []host.Command
	add := func(name string, args ...string) {
		cmds = append(cmds, host.Command{Name: name, Args: args, Mutates: true})
	}

	switch fw.Kind {
	case KindUFW:
		if !fw.Active {
			if len(sshPorts) == 0 {
				sshPorts = []int{22}
			}
			for _, p := range sshPorts {
				add("ufw", "allow", strconv.Itoa(p)+"/tcp", "comment", "SSH")
			}
		}
		add("ufw", "allow", port, "comment", "Tor relay ORPort")
		if enableUFW && !fw.Active {
			add("ufw", "--force", "enable")
		}
	case KindFirewalld:
		if fw.Active {
			add("firewall-cmd", "--permanent", "--add-port="+port)
			add("firewall-cmd", "--reload")
		}
	case KindNFTables:
		if fw.Detail == DetailNFTChainFound {
			add("nft", "add", "rule", "inet", "filter", "input", "tcp", "dport", strconv.Itoa(orPort),
				"accept", "comment", `"`+nftComment(orPort)+`"`)
		}
	}
	return cmds
}
