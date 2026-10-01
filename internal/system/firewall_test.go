package system

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func exitErr(c host.Command, code int) error {
	return &host.ExitError{Command: c.String(), ExitCode: code}
}

func TestDetectFirewall(t *testing.T) {
	tests := []struct {
		name    string
		paths   []string
		handler func(host.Command) (host.Result, error)
		want    Firewall
	}{
		{
			name:  "ufw active",
			paths: []string{"ufw", "firewall-cmd", "nft"},
			handler: func(c host.Command) (host.Result, error) {
				return host.Result{Output: "Status: active\n\nTo                         Action      From\n"}, nil
			},
			want: Firewall{Kind: KindUFW, Active: true, Detail: DetailActive},
		},
		{
			name:  "ufw inactive",
			paths: []string{"ufw"},
			handler: func(c host.Command) (host.Result, error) {
				return host.Result{Output: "Status: inactive\n"}, nil
			},
			want: Firewall{Kind: KindUFW, Detail: DetailInactive},
		},
		{
			name:  "ufw needs root",
			paths: []string{"ufw"},
			handler: func(c host.Command) (host.Result, error) {
				return host.Result{Output: "ERROR: You need to be root to run this script\n", ExitCode: 1}, exitErr(c, 1)
			},
			want: Firewall{Kind: KindUFW, Detail: DetailInstalled},
		},
		{
			name:  "firewalld active",
			paths: []string{"firewall-cmd", "nft"},
			handler: func(c host.Command) (host.Result, error) {
				if c.String() == "systemctl is-active --quiet firewalld" {
					return host.Result{}, nil
				}
				return host.Result{}, errors.New("unexpected " + c.String())
			},
			want: Firewall{Kind: KindFirewalld, Active: true, Detail: DetailActive},
		},
		{
			name:  "firewalld inactive",
			paths: []string{"firewall-cmd"},
			handler: func(c host.Command) (host.Result, error) {
				return host.Result{ExitCode: 3}, exitErr(c, 3)
			},
			want: Firewall{Kind: KindFirewalld, Detail: DetailInactive},
		},
		{
			name:  "nft chain present",
			paths: []string{"nft"},
			handler: func(c host.Command) (host.Result, error) {
				if c.String() == "nft list chain inet filter input" {
					return host.Result{Output: "table inet filter {\n\tchain input {\n\t}\n}\n"}, nil
				}
				return host.Result{}, errors.New("unexpected " + c.String())
			},
			want: Firewall{Kind: KindNFTables, Active: true, Detail: DetailNFTChainFound},
		},
		{
			name:  "nft chain absent",
			paths: []string{"nft"},
			handler: func(c host.Command) (host.Result, error) {
				return host.Result{Output: "Error: No such file or directory", ExitCode: 1}, exitErr(c, 1)
			},
			want: Firewall{Kind: KindNFTables, Detail: DetailNFTNoChain},
		},
		{
			name: "none",
			want: Firewall{Kind: KindNone, Detail: DetailNone},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := host.NewFake()
			for _, p := range tt.paths {
				f.Paths[p] = true
			}
			f.Handler = tt.handler
			if got := DetectFirewall(context.Background(), f); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			for _, c := range f.Commands {
				if c.Mutates {
					t.Errorf("detection ran mutating %s", c)
				}
			}
		})
	}
}

func TestNFTRuleExists(t *testing.T) {
	listing := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 9001 accept comment "Tor relay ORPort 9001"
	}
}
`
	f := host.NewFake()
	f.Handler = func(c host.Command) (host.Result, error) { return host.Result{Output: listing}, nil }
	if !NFTRuleExists(context.Background(), f, 9001) {
		t.Error("rule for 9001 not found")
	}
	if NFTRuleExists(context.Background(), f, 900) {
		t.Error("port 900 must not match the 9001 rule")
	}
	f.Handler = func(c host.Command) (host.Result, error) { return host.Result{Output: listing}, exitErr(c, 1) }
	if NFTRuleExists(context.Background(), f, 9001) {
		t.Error("failed listing must report false")
	}
}

func TestFirewallCommands(t *testing.T) {
	tests := []struct {
		name       string
		fw         Firewall
		ssh        []int
		enable     bool
		installUFW bool
		want       []string
	}{
		{
			name:   "ufw inactive with enable",
			fw:     Firewall{Kind: KindUFW, Detail: DetailInactive},
			ssh:    []int{22, 2222},
			enable: true,
			want: []string{
				"ufw allow 22/tcp comment SSH",
				"ufw allow 2222/tcp comment SSH",
				"ufw allow 9001/tcp comment 'Tor relay ORPort'",
				"ufw --force enable",
			},
		},
		{
			name: "ufw inactive without enable defaults ssh 22",
			fw:   Firewall{Kind: KindUFW, Detail: DetailInstalled},
			want: []string{
				"ufw allow 22/tcp comment SSH",
				"ufw allow 9001/tcp comment 'Tor relay ORPort'",
			},
		},
		{
			name:   "ufw active skips ssh and enable",
			fw:     Firewall{Kind: KindUFW, Active: true, Detail: DetailActive},
			ssh:    []int{22},
			enable: true,
			want:   []string{"ufw allow 9001/tcp comment 'Tor relay ORPort'"},
		},
		{
			name:       "install ufw on a machine without firewall",
			fw:         Firewall{Kind: KindNone, Detail: DetailNone},
			ssh:        []int{2022},
			enable:     true,
			installUFW: true,
			want: []string{
				"ufw allow 2022/tcp comment SSH",
				"ufw allow 9001/tcp comment 'Tor relay ORPort'",
				"ufw --force enable",
			},
		},
		{
			name: "firewalld active",
			fw:   Firewall{Kind: KindFirewalld, Active: true, Detail: DetailActive},
			want: []string{"firewall-cmd --permanent --add-port=9001/tcp", "firewall-cmd --reload"},
		},
		{
			name: "firewalld inactive",
			fw:   Firewall{Kind: KindFirewalld, Detail: DetailInactive},
		},
		{
			name: "nft chain",
			fw:   Firewall{Kind: KindNFTables, Active: true, Detail: DetailNFTChainFound},
			want: []string{`nft add rule inet filter input tcp dport 9001 accept comment '"Tor relay ORPort 9001"'`},
		},
		{
			name: "nft without chain",
			fw:   Firewall{Kind: KindNFTables, Detail: DetailNFTNoChain},
		},
		{
			name: "none",
			fw:   Firewall{Kind: KindNone, Detail: DetailNone},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := FirewallCommands(tt.fw, 9001, tt.ssh, tt.enable, tt.installUFW)
			var got []string
			for _, c := range cmds {
				if !c.Mutates {
					t.Errorf("%s must be Mutates", c)
				}
				got = append(got, c.String())
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestFirewallCommandsNFTArgv(t *testing.T) {
	// nft joins its argv and parses it, so the comment keeps its quotes.
	cmds := FirewallCommands(Firewall{Kind: KindNFTables, Detail: DetailNFTChainFound}, 443, nil, false, false)
	want := []string{"add", "rule", "inet", "filter", "input", "tcp", "dport", "443", "accept", "comment", `"Tor relay ORPort 443"`}
	if len(cmds) != 1 || cmds[0].Name != "nft" || !reflect.DeepEqual(cmds[0].Args, want) {
		t.Errorf("got %+v", cmds)
	}
}
