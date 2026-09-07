package lsec

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type privateTempWorkspace struct {
	dir string
}

func newPrivateTempWorkspace(pattern string) (*privateTempWorkspace, error) {
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &privateTempWorkspace{dir: dir}, nil
}

func (w *privateTempWorkspace) remove() {
	if w != nil && w.dir != "" {
		_ = os.RemoveAll(w.dir)
	}
}

func (w *privateTempWorkspace) path(name string) (string, error) {
	if w == nil || w.dir == "" {
		return "", fmt.Errorf("private temporary workspace is unavailable")
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid private temporary filename %q", name)
	}
	return filepath.Join(w.dir, name), nil
}

func (w *privateTempWorkspace) writeExclusive(name string, body []byte) (string, error) {
	path, err := w.path(name)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	remove := true
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(body); err != nil {
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		return "", err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return "", err
	}
	remove = false
	return path, nil
}

func (w *privateTempWorkspace) readRegular(name string) ([]byte, error) {
	path, err := w.path(name)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("private temporary result %q is not a regular file", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("private temporary result %q changed before it was read", name)
	}
	return io.ReadAll(f)
}
