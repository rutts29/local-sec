package lsec

import (
	"os"
	"path/filepath"
	"time"
)

type Paths struct {
	Root          string
	Bin           string
	DB            string
	Logs          string
	Events        string
	Staging       string
	Scans         string
	Approvals     string
	AdvisoryCache string
}

func DefaultPaths() (Paths, error) {
	if override := os.Getenv("LSEC_HOME"); override != "" {
		root := filepath.Clean(override)
		return pathsFromRoot(root), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	return pathsFromRoot(filepath.Join(home, ".local-sec")), nil
}

func pathsFromRoot(root string) Paths {
	return Paths{
		Root:          root,
		Bin:           filepath.Join(root, "bin"),
		DB:            filepath.Join(root, "db", "local-sec.db"),
		Logs:          filepath.Join(root, "logs"),
		Events:        filepath.Join(root, "logs", "events.jsonl"),
		Staging:       filepath.Join(root, "staging"),
		Scans:         filepath.Join(root, "scans"),
		Approvals:     filepath.Join(root, "approvals.json"),
		AdvisoryCache: filepath.Join(root, "advisory-cache.json"),
	}
}

func (p Paths) Ensure() error {
	for _, dir := range []string{p.Root, p.Bin, filepath.Dir(p.DB), p.Logs, p.Staging, p.Scans, filepath.Dir(p.Approvals)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func NewRunID(now time.Time) string {
	return now.UTC().Format("20060102T150405.000000000")
}
