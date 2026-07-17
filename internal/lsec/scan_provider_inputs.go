package lsec

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type providerInputSelection struct {
	accepted       []string
	candidateCount int
	skipReasons    map[string]int
}

type providerInputCopy struct {
	original string
	copied   string
}

func (s providerInputSelection) snapshot(provider, status string, queriedCount, failedCount int, errorCategory string) ScanProviderSnapshot {
	return ScanProviderSnapshot{
		Provider: provider, Status: status, CandidateCount: s.candidateCount, AcceptedCount: len(s.accepted),
		SkippedCount: s.candidateCount - len(s.accepted), QueriedCount: queriedCount, FailedCount: failedCount,
		SkipReasons: s.skipReasons, Error: errorCategory,
	}
}

func (s *providerInputSelection) skip(reason string) {
	if s.skipReasons == nil {
		s.skipReasons = map[string]int{}
	}
	s.skipReasons[reason]++
}

func (s *providerInputSelection) revalidate() {
	for _, path := range append([]string(nil), s.accepted...) {
		s.revalidatePath(path)
	}
}

func (s *providerInputSelection) revalidatePath(path string) bool {
	reason := providerInputRejection(path)
	if reason == "" {
		return true
	}
	s.rejectAcceptedPath(path, reason)
	return false
}

func (s *providerInputSelection) rejectAcceptedPath(path, reason string) {
	for i, accepted := range s.accepted {
		if accepted == path {
			s.accepted = append(s.accepted[:i], s.accepted[i+1:]...)
			break
		}
	}
	s.skip(reason)
}

func providerInputRejection(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return "inaccessible"
	}
	return providerInputInfoRejection(info)
}

func providerInputInfoRejection(info os.FileInfo) string {
	if info.Mode()&os.ModeSymlink != 0 {
		return "symlink"
	}
	if !info.Mode().IsRegular() {
		return "non_regular"
	}
	return providerInputLinkRejection(info)
}

func (s *providerInputSelection) copyAcceptedToProviderDir(dir string, preserveBase bool) ([]providerInputCopy, error) {
	inputDir := filepath.Join(dir, "inputs")
	if err := os.MkdirAll(inputDir, 0o700); err != nil {
		return nil, err
	}
	var copies []providerInputCopy
	for index, original := range append([]string(nil), s.accepted...) {
		copy, ok, err := s.copyAcceptedPathToProviderDir(inputDir, index, original, preserveBase)
		if err != nil {
			return nil, err
		}
		if ok {
			copies = append(copies, copy)
		}
	}
	if len(copies) == 0 {
		return nil, errNoProviderInputs
	}
	return copies, nil
}

func (s *providerInputSelection) copyAcceptedPathToProviderDir(inputDir string, index int, original string, preserveBase bool) (providerInputCopy, bool, error) {
	copied := filepath.Join(inputDir, providerInputCopyName(index, original, preserveBase))
	reason, err := copyProviderInputFile(original, copied)
	if reason != "" {
		s.rejectAcceptedPath(original, reason)
		return providerInputCopy{}, false, nil
	}
	if err != nil {
		return providerInputCopy{}, false, err
	}
	return providerInputCopy{original: original, copied: copied}, true, nil
}

func providerInputCopyName(index int, original string, preserveBase bool) string {
	if preserveBase {
		return fmt.Sprintf("input-%03d-%s", index, filepath.Base(original))
	}
	ext := filepath.Ext(original)
	if ext == "" || strings.ContainsAny(ext, string(os.PathSeparator)) {
		ext = ".input"
	}
	return fmt.Sprintf("input-%03d%s", index, ext)
}

func copyProviderInputFile(original, copied string) (string, error) {
	before, err := os.Lstat(original)
	if err != nil {
		return "inaccessible", nil
	}
	if reason := providerInputInfoRejection(before); reason != "" {
		return reason, nil
	}
	src, err := os.Open(original)
	if err != nil {
		return "inaccessible", nil
	}
	defer src.Close()
	opened, err := src.Stat()
	if err != nil {
		return "inaccessible", nil
	}
	if reason := providerInputInfoRejection(opened); reason != "" {
		return reason, nil
	}
	after, err := os.Lstat(original)
	if err != nil {
		return "inaccessible", nil
	}
	if reason := providerInputInfoRejection(after); reason != "" {
		return reason, nil
	}
	if !os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return "changed_during_validation", nil
	}
	dst, err := os.OpenFile(copied, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}
	return "", nil
}

func providerSourcePathMap(copies []providerInputCopy) map[string]string {
	paths := map[string]string{}
	for _, copy := range copies {
		paths[copy.copied] = copy.original
		paths[filepath.Clean(copy.copied)] = copy.original
	}
	return paths
}

func grypeCycloneDXSBOMFilesFromObservations(observations []ScanObservation) providerInputSelection {
	seen := map[string]bool{}
	var selection providerInputSelection
	for _, observation := range observations {
		if observation.SourceType != "cyclonedx_sbom" {
			continue
		}
		selection.candidateCount++
		if observation.SourcePath == "" {
			selection.skip("missing_path")
			continue
		}
		clean := filepath.Clean(observation.SourcePath)
		if seen[clean] {
			selection.skip("duplicate")
			continue
		}
		seen[clean] = true
		if reason := providerInputRejection(clean); reason != "" {
			selection.skip(reason)
			continue
		}
		selection.accepted = append(selection.accepted, clean)
	}
	sort.Strings(selection.accepted)
	return selection
}

func collectOSVScannerLockfiles(roots []string) providerInputSelection {
	seen := map[string]bool{}
	var selection providerInputSelection
	for _, root := range roots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if isOSVScannerLockfile(path) && !seen[path] {
					seen[path] = true
					selection.candidateCount++
					selection.skip("inaccessible")
				}
				return nil
			}
			clean := filepath.Clean(path)
			if entry.Type()&os.ModeSymlink != 0 {
				if isOSVScannerLockfile(path) && !seen[clean] {
					seen[clean] = true
					selection.candidateCount++
					selection.skip("symlink")
				}
				return nil
			}
			if entry.IsDir() && entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			if entry.IsDir() {
				return nil
			}
			if !isOSVScannerLockfile(path) || seen[clean] {
				return nil
			}
			seen[clean] = true
			selection.candidateCount++
			if reason := providerInputRejection(clean); reason != "" {
				selection.skip(reason)
				return nil
			}
			selection.accepted = append(selection.accepted, clean)
			return nil
		})
	}
	sort.Strings(selection.accepted)
	return selection
}

func isOSVScannerLockfile(path string) bool {
	base := filepath.Base(path)
	return base == "package-lock.json" || base == "npm-shrinkwrap.json"
}

func collectPipAuditRequirementsFiles(roots []string) providerInputSelection {
	seen := map[string]bool{}
	var selection providerInputSelection
	for _, root := range roots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if filepath.Base(path) == "requirements.txt" && !seen[path] {
					seen[path] = true
					selection.candidateCount++
					selection.skip("inaccessible")
				}
				return nil
			}
			clean := filepath.Clean(path)
			if entry.Type()&os.ModeSymlink != 0 {
				if filepath.Base(path) == "requirements.txt" && !seen[clean] {
					seen[clean] = true
					selection.candidateCount++
					selection.skip("symlink")
				}
				return nil
			}
			if entry.IsDir() {
				if skipPipAuditDir(entry.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Base(path) != "requirements.txt" || seen[clean] {
				return nil
			}
			seen[clean] = true
			selection.candidateCount++
			if reason := providerInputRejection(clean); reason != "" {
				selection.skip(reason)
				return nil
			}
			specs, findings := ParseRequirementsFiles([]string{clean})
			if len(specs) == 0 || len(findings) > 0 {
				selection.skip("unsafe_requirements")
				return nil
			}
			selection.accepted = append(selection.accepted, clean)
			return nil
		})
	}
	sort.Strings(selection.accepted)
	return selection
}

func skipPipAuditDir(name string) bool {
	switch name {
	case "node_modules", ".venv", ".env", "venv", "env", "site-packages":
		return true
	default:
		return false
	}
}
