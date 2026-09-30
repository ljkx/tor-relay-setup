# Guided setup in fzf mode, as a dry run. Recorded with VHS
# (https://github.com/charmbracelet/vhs); re-record with `make demo`.
# Each block answers one prompt of the real script.

Output "docs/assets/demo.gif"

Require fzf

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 15
Set LineHeight 1.25
Set Width 1400
Set Height 800
Set Padding 22
Set Margin 26
Set MarginFill "#7D4698"
Set WindowBar Colorful
Set BorderRadius 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Set CursorBlink false

Hide
Type "source docs/demo/demo-env.sh"
Enter
Sleep 700ms
Show

Type "./setup-tor-guard-relay.sh --dry-run"
Sleep 600ms
Enter
Sleep 2.5s

# Hostname: keep.
Type "n"
Sleep 1s

# Relay mode: guard/middle.
Type "n"
Sleep 1.2s

# Identity: nickname, CIISS v3 ContactInfo (email, website, no hoster), ORPort 9001.
Type "ExampleRelay"
Sleep 400ms
Enter
Sleep 1s
Enter
Sleep 1s
Type "ops@example.org"
Sleep 300ms
Enter
Sleep 800ms
Type "https://example.org"
Sleep 300ms
Enter
Sleep 800ms
Enter
Sleep 1.2s
Enter
Sleep 1s

# No IPv6.
Type "n"
Sleep 1s

# Create a new relay family key (default name), skip legacy MyFamily.
Type "2"
Sleep 1s
Enter
Sleep 900ms
Type "n"
Sleep 1.2s

# Steady monthly budget: 10TB, 10% headroom, combined in+out.
Enter
Sleep 1s
Type "10TB"
Sleep 300ms
Enter
Sleep 800ms
Enter
Sleep 800ms
Enter
Sleep 2s

# Maintenance: unattended upgrades, Nyx, MetricsPort, UFW, Sandbox.
Enter
Sleep 800ms
Enter
Sleep 800ms
Type "y"
Sleep 800ms
Enter
Sleep 800ms
Enter
Sleep 4s

# Review everything, including the generated torrc.
PageDown
Sleep 2s
PageDown
Sleep 2.5s
Enter
Sleep 1s

# Confirm. In a dry run this only prints the planned commands.
Type "y"
Sleep 4s
