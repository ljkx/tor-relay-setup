package host

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fake is an in-memory Host for tests. Files live in a map, commands are
// recorded, and Handler decides each command's result.
type Fake struct {
	mu       sync.Mutex
	Files    map[string][]byte
	Modes    map[string]fs.FileMode
	Owners   map[string]string
	Dirs     map[string]bool
	Commands []Command
	// Handler returns the result for a command; nil means success, no output.
	Handler func(Command) (Result, error)
	// Paths lists executables LookPath should find.
	Paths map[string]bool
	// Links maps symlink paths to their targets.
	Links map[string]string
	Dry   bool
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{
		Files:  map[string][]byte{},
		Modes:  map[string]fs.FileMode{},
		Owners: map[string]string{},
		Dirs:   map[string]bool{},
		Paths:  map[string]bool{},
		Links:  map[string]string{},
	}
}

// DryRun reports the Dry field.
func (f *Fake) DryRun() bool { return f.Dry }

// Run records c and returns Handler's result.
func (f *Fake) Run(ctx context.Context, c Command) (Result, error) {
	return f.Stream(ctx, c, nil)
}

// Stream records c, returns Handler's result, and feeds its output to onLine.
func (f *Fake) Stream(_ context.Context, c Command, onLine func(string)) (Result, error) {
	f.mu.Lock()
	f.Commands = append(f.Commands, c)
	handler := f.Handler
	f.mu.Unlock()
	if f.Dry && c.Mutates {
		return Result{}, nil
	}
	if handler == nil {
		return Result{}, nil
	}
	res, err := handler(c)
	if onLine != nil {
		for _, line := range strings.Split(strings.TrimRight(res.Output, "\n"), "\n") {
			if line != "" {
				onLine(line)
			}
		}
	}
	return res, err
}

// Ran reports whether a command line containing all substrings was recorded.
func (f *Fake) Ran(substrings ...string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.Commands {
		line := c.String()
		all := true
		for _, s := range substrings {
			if !strings.Contains(line, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// CommandLines returns every recorded command as a string.
func (f *Fake) CommandLines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.Commands))
	for i, c := range f.Commands {
		out[i] = c.String()
	}
	return out
}

// ReadFile returns a stored file.
func (f *Fake) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.Files[p]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	return bytes.Clone(data), nil
}

// WriteFile stores a file (or only reports when Dry is set).
func (f *Fake) WriteFile(p string, data []byte, opt FileOptions) (Change, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := Change{Path: p}
	old, exists := f.Files[p]
	switch {
	case exists && bytes.Equal(old, data):
		ch.Unchanged = true
		return ch, nil
	case exists && opt.Backup:
		ch.BackupOf = p + ".bak.test"
		if !f.Dry {
			f.Files[ch.BackupOf] = old
		}
	case !exists:
		ch.Created = true
	}
	if f.Dry {
		return ch, nil
	}
	f.Files[p] = bytes.Clone(data)
	mode := opt.Mode
	if mode == 0 {
		mode = 0o644
	}
	f.Modes[p] = mode
	f.Owners[p] = opt.Owner
	return ch, nil
}

// CopyFile copies one stored file to another path.
func (f *Fake) CopyFile(src, dst string, opt FileOptions) (Change, error) {
	data, err := f.ReadFile(src)
	if err != nil {
		return Change{Path: dst}, err
	}
	return f.WriteFile(dst, data, opt)
}

// MkdirAll records a directory.
func (f *Fake) MkdirAll(p string, perm fs.FileMode, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Dry {
		f.Dirs[p] = true
		f.Modes[p] = perm | fs.ModeDir
		f.Owners[p] = owner
	}
	return nil
}

// Remove deletes a file, or every file under a directory.
func (f *Fake) Remove(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Dry {
		return nil
	}
	for k := range f.Files {
		if k == p || strings.HasPrefix(k, p+"/") {
			delete(f.Files, k)
		}
	}
	delete(f.Dirs, p)
	return nil
}

// Stat reports stored files and directories.
func (f *Fake) Stat(p string) (fs.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if data, ok := f.Files[p]; ok {
		return fakeInfo{name: filepath.Base(p), size: int64(len(data)), mode: f.Modes[p]}, nil
	}
	if f.Dirs[p] {
		return fakeInfo{name: filepath.Base(p), mode: fs.ModeDir | 0o755}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}

// Glob matches stored file paths.
func (f *Fake) Glob(pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for p := range f.Files {
		if ok, err := filepath.Match(pattern, p); err != nil {
			return nil, err
		} else if ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Readlink returns a target from Links.
func (f *Fake) Readlink(p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.Links[p]; ok {
		return t, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
}

// Symlink records a link, replacing any file at path.
func (f *Fake) Symlink(target, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Dry {
		delete(f.Files, p)
		f.Links[p] = target
	}
	return nil
}

// LookPath finds names listed in Paths.
func (f *Fake) LookPath(name string) (string, error) {
	if f.Paths[name] {
		return "/usr/bin/" + name, nil
	}
	return "", fmt.Errorf("%s: not found", name)
}

type fakeInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return i.size }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fakeInfo) Sys() any           { return nil }
