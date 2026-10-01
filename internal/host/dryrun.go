package host

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
)

// DryRun reads the real system but never changes it: read-only commands run
// normally, mutating commands and file writes are only reported.
type DryRun struct {
	*Local
}

// NewDryRun wraps a Local host.
func NewDryRun(l *Local) *DryRun { return &DryRun{Local: l} }

// DryRun reports true.
func (d *DryRun) DryRun() bool { return true }

// Run runs read-only commands and reports mutating ones.
func (d *DryRun) Run(ctx context.Context, c Command) (Result, error) {
	return d.Stream(ctx, c, nil)
}

// Stream runs read-only commands and reports mutating ones.
func (d *DryRun) Stream(ctx context.Context, c Command, onLine func(string)) (Result, error) {
	if !c.Mutates {
		return d.Local.Stream(ctx, c, onLine)
	}
	d.emit(Event{Kind: EventCommand, Text: c.String(), Dry: true})
	return Result{}, nil
}

// WriteFile reports what would change without writing.
func (d *DryRun) WriteFile(p string, data []byte, opt FileOptions) (Change, error) {
	ch := Change{Path: p}
	old, err := os.ReadFile(d.path(p))
	switch {
	case err == nil && bytes.Equal(old, data):
		ch.Unchanged = true
		return ch, nil
	case err == nil && opt.Backup:
		ch.BackupOf = p + ".bak." + d.Stamp
	case errors.Is(err, fs.ErrNotExist):
		ch.Created = true
	case err != nil && !errors.Is(err, fs.ErrPermission):
		return ch, err
	}
	d.emit(Event{Kind: EventFile, Text: "would write " + p, Dry: true})
	return ch, nil
}

// CopyFile reports the copy without reading or writing.
func (d *DryRun) CopyFile(src, dst string, opt FileOptions) (Change, error) {
	d.emit(Event{Kind: EventFile, Text: "would install " + src + " as " + dst, Dry: true})
	return Change{Path: dst, Created: true}, nil
}

// MkdirAll reports a directory that would be created.
func (d *DryRun) MkdirAll(p string, perm fs.FileMode, owner string) error {
	if _, err := os.Stat(d.path(p)); err == nil {
		return nil
	}
	d.emit(Event{Kind: EventFile, Text: "would create " + p, Dry: true})
	return nil
}

// Remove reports a removal.
func (d *DryRun) Remove(p string) error {
	d.emit(Event{Kind: EventFile, Text: "would remove " + p, Dry: true})
	return nil
}

// Symlink reports a link that would be created.
func (d *DryRun) Symlink(target, p string) error {
	d.emit(Event{Kind: EventFile, Text: "would link " + p + " -> " + target, Dry: true})
	return nil
}
