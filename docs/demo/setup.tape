# The setup wizard as a dry run. Recorded with VHS
# (https://github.com/charmbracelet/vhs); re-record with `make demo`.
# docs/demo/demo-env.sh provides a fixture server, so nothing is changed.

Output "docs/assets/setup.gif"

Require tor-relay-setup

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set LineHeight 1.2
Set Width 1400
Set Height 860
Set Padding 18
Set Margin 24
Set MarginFill "#7D4698"
Set WindowBar Colorful
Set BorderRadius 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set CursorBlink false

Hide
Type "source docs/demo/demo-env.sh fresh"
Enter
Sleep 500ms
Show

Type "tor-relay-setup setup --dry-run"
Sleep 500ms
Enter
Sleep 2s

# Relay: guard/middle, nickname.
Enter
Sleep 600ms
Type "ExampleRelay"
Sleep 400ms
Enter
Sleep 800ms

# Contact: guided CIISS v3 (watch the torrc preview on the right).
Enter
Sleep 500ms
Type "ops@example.org"
Enter
Sleep 300ms
Type "https://example.org"
Enter
Sleep 300ms
Enter
Sleep 900ms

# Network: ORPort 9001, no IPv6.
Enter
Sleep 400ms
Enter
Sleep 900ms

# Family: create a new FamilyId key.
Down
Sleep 500ms
Enter
Sleep 400ms
Enter
Sleep 900ms

# Bandwidth: pace a 10 TB monthly quota.
Enter
Sleep 400ms
Type "10TB"
Sleep 500ms
Enter
Sleep 400ms
Enter
Sleep 1.5s
Enter
Sleep 900ms

# System: updates, Nyx, MetricsPort, firewall, UFW, Sandbox.
Enter
Sleep 300ms
Enter
Sleep 300ms
Enter
Sleep 300ms
Type "y"
Sleep 700ms
Enter
Sleep 500ms
Enter
Sleep 500ms
Enter
Sleep 2s

# Review everything before anything changes.
Down 6
Sleep 1s
PageDown
Sleep 2s
Type "a"
Sleep 900ms
Type "y"

# Apply (dry run): the live checklist.
Sleep 7s
Type "l"
Sleep 3s
