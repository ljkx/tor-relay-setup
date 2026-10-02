// Package host is the only place that touches the machine: it runs commands
// and reads or writes files. Every installer step goes through a Host, so a
// dry run and the tests can swap in implementations that change nothing.
package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Command describes one external program invocation.
type Command struct {
	Name string
	Args []string
	Env  []string // extra KEY=VALUE pairs on top of the current environment
	Dir  string
	// Mutates marks commands that change the system. A dry run prints them
	// instead of running them; read-only commands always run.
	Mutates bool
	// StatusFD, when set, receives the lines a program writes to file
	// descriptor 3 (apt's machine-readable APT::Status-Fd progress).
	StatusFD func(line string)
	// Stdin, when not nil, is the program's standard input; otherwise it
	// reads from the null device. It is never logged or shown in dry runs.
	Stdin []byte
}

// String renders the command as a shell-quoted line for logs and dry runs.
func (c Command) String() string {
	parts := make([]string, 0, len(c.Args)+1+len(c.Env))
	parts = append(parts, c.Env...)
	parts = append(parts, c.Name)
	parts = append(parts, c.Args...)
	for i, p := range parts {
		parts[i] = Quote(p)
	}
	return strings.Join(parts, " ")
}

// Result is the captured outcome of a command.
type Result struct {
	Output   string
	ExitCode int
	Duration time.Duration
}

// FileOptions controls WriteFile.
type FileOptions struct {
	Mode  fs.FileMode
	Owner string // user name; group is the user's primary group. Empty keeps root.
	// Backup copies an existing, different file to <path>.bak.<timestamp>
	// before it is replaced.
	Backup bool
}

// Change reports what WriteFile did.
type Change struct {
	Path      string
	Unchanged bool
	Created   bool
	BackupOf  string // backup path, when one was made
}

// EventKind classifies host events for observers such as the TUI log pane.
type EventKind int

const (
	EventCommand EventKind = iota // a command is about to run (or would run)
	EventOutput                   // one line of command output
	EventFile                     // a file was (or would be) written or removed
)

// Event is emitted for every command, output line, and file change.
type Event struct {
	Kind EventKind
	Text string
	Dry  bool
}

// Host abstracts the machine the installer runs on.
type Host interface {
	Run(ctx context.Context, c Command) (Result, error)
	Stream(ctx context.Context, c Command, onLine func(string)) (Result, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, opt FileOptions) (Change, error)
	CopyFile(src, dst string, opt FileOptions) (Change, error)
	MkdirAll(path string, perm fs.FileMode, owner string) error
	Remove(path string) error
	Stat(path string) (fs.FileInfo, error)
	Glob(pattern string) ([]string, error)
	Readlink(path string) (string, error)
	Symlink(target, path string) error
	LookPath(name string) (string, error)
	DryRun() bool
}

// ExitError is returned when a command exits non-zero.
type ExitError struct {
	Command  string
	ExitCode int
	Output   string
}

func (e *ExitError) Error() string {
	tail := lastLines(e.Output, 6)
	if tail == "" {
		return fmt.Sprintf("%s exited with status %d", e.Command, e.ExitCode)
	}
	return fmt.Sprintf("%s exited with status %d:\n%s", e.Command, e.ExitCode, tail)
}

// Local runs commands and changes files on this machine.
type Local struct {
	// Root prefixes every file path (tests point it at a temp dir). Commands
	// are not affected.
	Root string
	// Stamp names backups; it is fixed per run so related backups match.
	Stamp string
	// Observe, when set, receives every event.
	Observe func(Event)

	mu sync.Mutex
}

// NewLocal returns a Local host with a UTC timestamp for backups.
func NewLocal() *Local {
	return &Local{Stamp: time.Now().UTC().Format("20060102T150405Z")}
}

func (l *Local) emit(e Event) {
	if l.Observe != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.Observe(e)
	}
}

func (l *Local) path(p string) string {
	if l.Root == "" {
		return p
	}
	return filepath.Join(l.Root, p)
}

// DryRun reports false: Local changes the system.
func (l *Local) DryRun() bool { return false }

// Run executes c and captures its combined output.
func (l *Local) Run(ctx context.Context, c Command) (Result, error) {
	return l.Stream(ctx, c, nil)
}

// Stream executes c, reporting each output line to onLine as it arrives.
func (l *Local) Stream(ctx context.Context, c Command, onLine func(string)) (Result, error) {
	l.emit(Event{Kind: EventCommand, Text: c.String()})
	start := time.Now()

	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.WaitDelay = 5 * time.Second
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}

	var out bytes.Buffer
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	var statusR, statusW *os.File
	if c.StatusFD != nil {
		var err error
		statusR, statusW, err = os.Pipe()
		if err != nil {
			return Result{}, err
		}
		cmd.ExtraFiles = []*os.File{statusW} // becomes fd 3 in the child
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			out.WriteString(line)
			out.WriteByte('\n')
			l.emit(Event{Kind: EventOutput, Text: line})
			if onLine != nil {
				onLine(line)
			}
		}
		_, _ = io.Copy(io.Discard, pr)
	}()
	if statusR != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := bufio.NewScanner(statusR)
			for sc.Scan() {
				c.StatusFD(sc.Text())
			}
		}()
	}

	err := cmd.Start()
	if statusW != nil {
		_ = statusW.Close() // the child holds its own copy
	}
	if err == nil {
		err = cmd.Wait()
	}
	_ = pw.Close()
	wg.Wait()
	if statusR != nil {
		_ = statusR.Close()
	}

	res := Result{Output: out.String(), Duration: time.Since(start)}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, &ExitError{Command: c.String(), ExitCode: res.ExitCode, Output: res.Output}
		}
		return res, fmt.Errorf("%s: %w", c.Name, err)
	}
	return res, nil
}

// ReadFile reads a file.
func (l *Local) ReadFile(p string) ([]byte, error) { return os.ReadFile(l.path(p)) }

// Stat stats a file.
func (l *Local) Stat(p string) (fs.FileInfo, error) { return os.Stat(l.path(p)) }

// Glob expands a pattern and returns paths without the Root prefix.
func (l *Local) Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(l.path(pattern))
	if err != nil || l.Root == "" {
		return matches, err
	}
	for i, m := range matches {
		matches[i] = strings.TrimPrefix(m, l.Root)
	}
	return matches, nil
}

// Readlink returns a symlink's target, or an error when path is no symlink.
func (l *Local) Readlink(p string) (string, error) { return os.Readlink(l.path(p)) }

// Symlink atomically points path at target, replacing what was there.
func (l *Local) Symlink(target, p string) error {
	link := l.path(p)
	tmp := link + ".tmp-link"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	l.emit(Event{Kind: EventFile, Text: "linked " + p + " -> " + target})
	return nil
}

// LookPath finds an executable in PATH.
func (l *Local) LookPath(name string) (string, error) { return exec.LookPath(name) }

// WriteFile atomically replaces path with data. Identical content is left
// alone; a different existing file is backed up first when opt.Backup is set.
func (l *Local) WriteFile(p string, data []byte, opt FileOptions) (Change, error) {
	target := l.path(p)
	ch := Change{Path: p}

	old, err := os.ReadFile(target)
	switch {
	case err == nil && bytes.Equal(old, data):
		ch.Unchanged = true
		return ch, nil
	case err == nil && opt.Backup:
		backup, berr := l.backup(p)
		if berr != nil {
			return ch, berr
		}
		ch.BackupOf = backup
	case errors.Is(err, fs.ErrNotExist):
		ch.Created = true
	case err != nil:
		return ch, err
	}

	mode := opt.Mode
	if mode == 0 {
		mode = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return ch, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return ch, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return ch, err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return ch, err
	}
	if err := chownFile(tmp, opt.Owner); err != nil {
		_ = tmp.Close()
		return ch, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return ch, err
	}
	if err := tmp.Close(); err != nil {
		return ch, err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return ch, err
	}
	l.emit(Event{Kind: EventFile, Text: describeChange(ch)})
	return ch, nil
}

// CopyFile writes the content of src (a real path, not under Root) to dst.
func (l *Local) CopyFile(src, dst string, opt FileOptions) (Change, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return Change{Path: dst}, err
	}
	return l.WriteFile(dst, data, opt)
}

func (l *Local) backup(p string) (string, error) {
	base := p + ".bak." + l.Stamp
	candidate := base
	for i := 1; ; i++ {
		if _, err := os.Lstat(l.path(candidate)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		candidate = base + "." + strconv.Itoa(i)
	}
	src, err := os.Open(l.path(p))
	if err != nil {
		return "", err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return "", err
	}
	dst, err := os.OpenFile(l.path(candidate), os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return "", err
	}
	return candidate, dst.Close()
}

// MkdirAll creates a directory (and parents) owned by owner.
func (l *Local) MkdirAll(p string, perm fs.FileMode, owner string) error {
	target := l.path(p)
	if _, err := os.Stat(target); err == nil {
		return nil
	}
	if err := os.MkdirAll(target, perm); err != nil {
		return err
	}
	if err := os.Chmod(target, perm); err != nil {
		return err
	}
	l.emit(Event{Kind: EventFile, Text: "created " + p})
	return chownPath(target, owner)
}

// Remove deletes a file or directory tree.
func (l *Local) Remove(p string) error {
	if err := os.RemoveAll(l.path(p)); err != nil {
		return err
	}
	l.emit(Event{Kind: EventFile, Text: "removed " + p})
	return nil
}

func lookupOwner(owner string) (uid, gid int, ok bool, err error) {
	if owner == "" || os.Geteuid() != 0 {
		return 0, 0, false, nil
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return 0, 0, false, fmt.Errorf("unknown user %q: %w", owner, err)
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, true, nil
}

func chownFile(f *os.File, owner string) error {
	uid, gid, ok, err := lookupOwner(owner)
	if err != nil || !ok {
		return err
	}
	return f.Chown(uid, gid)
}

func chownPath(p, owner string) error {
	uid, gid, ok, err := lookupOwner(owner)
	if err != nil || !ok {
		return err
	}
	return os.Chown(p, uid, gid)
}

func describeChange(ch Change) string {
	switch {
	case ch.Unchanged:
		return "unchanged " + ch.Path
	case ch.Created:
		return "created " + ch.Path
	case ch.BackupOf != "":
		return "updated " + ch.Path + " (backup " + ch.BackupOf + ")"
	default:
		return "updated " + ch.Path
	}
}

// Quote shell-quotes s when needed, for display only.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !isShellSafe(r) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func isShellSafe(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,[]", r)
}
