package lsec

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyReleaseArtifactsFailsWhenExpectedArchiveMissing(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	name := "lsec_0.1.0_darwin_arm64"
	writeReleaseArchive(t, dist, name, map[string]string{
		name + "/lsec":      "binary",
		name + "/README.md": "readme",
		name + "/VERSION":   "0.1.0\n",
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded with missing expected archives")
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveMissingBinary(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		files := map[string]string{
			name + "/README.md": "readme",
			name + "/VERSION":   "0.1.0\n",
		}
		if target != "linux_amd64" {
			binary := "lsec"
			if target == "windows_amd64" {
				binary = "lsec.exe"
			}
			files[name+"/"+binary] = "binary"
		}
		writeReleaseArchive(t, dist, name, files)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when an archive was missing its binary")
	}
}

func TestBuildReleaseNormalizesTagVersionForVerifier(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"DIST="+dist,
		"VERSION=v0.1.0",
		"COMMIT=testcommit",
		"DATE=2026-01-01T00:00:00Z",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-release failed: %v\n%s", err, out)
	}

	verify := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	verify.Dir = root
	verify.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("verify-release-artifacts failed after tag-style VERSION build: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(dist)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "v0.1.0") {
			t.Fatalf("artifact name %q still contains tag prefix", entry.Name())
		}
	}
}

func releaseTargetsForTest() []string {
	return []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64"}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}

func writeReleaseArchive(t *testing.T, dist, name string, files map[string]string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dist, name+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for path, body := range files {
		hdr := &tar.Header{Name: path, Mode: 0o600, Size: int64(len(body))}
		if filepath.Base(path) == "lsec" || filepath.Base(path) == "lsec.exe" {
			hdr.Mode = 0o700
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeChecksums(t *testing.T, dist string) {
	t.Helper()
	entries, err := os.ReadDir(dist)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".gz" {
			continue
		}
		path := filepath.Join(dist, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		body += hex.EncodeToString(sum[:]) + "  " + entry.Name() + "\n"
	}
	if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
