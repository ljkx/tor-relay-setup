# The operator console on a running relay (fixture, dry run). Recorded with
# VHS; re-record with `make demo`.

Output "docs/assets/console.gif"

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
Type "source docs/demo/demo-env.sh"
Enter
Sleep 500ms
Show

Type "tor-relay-setup --dry-run"
Sleep 500ms
Enter
Sleep 4s

# Move through the actions.
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 800ms

# Live Tor log, streamed in place.
Type "l"
Sleep 6s
Escape
Sleep 1.5s

# Relay family: status and how to share the key.
Type "f"
Sleep 1.5s
Type "s"
Sleep 3s
Escape
Sleep 1.5s

# Update Tor (dry run shows the commands it would run).
Type "u"
Sleep 3s
Enter
Sleep 2s
