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
	writeReleaseArchive(t, dist, name, releaseFilesForTest(name, "lsec"))
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
		files := releaseFilesForTest(name, "")
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

func TestVerifyReleaseArtifactsFailsWhenArchiveContainsUnexpectedEntry(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		if target == "linux_amd64" {
			files[name+"/extra.txt"] = "unexpected"
		}
		writeReleaseArchive(t, dist, name, files)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("verify-release-artifacts succeeded when an archive contained an unexpected entry")
	}
	if !strings.Contains(string(out), "unexpected archive member") {
		t.Fatalf("verify-release-artifacts failed without reporting the unexpected member:\n%s", out)
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveContainsDuplicateAllowedMember(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		if target == "linux_amd64" {
			writeReleaseArchiveWithExtraHeaders(t, dist, name, files, []tar.Header{{
				Name: name + "/README.md",
				Mode: 0o600,
			}})
			continue
		}
		writeReleaseArchive(t, dist, name, files)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when an archive contained a duplicate allowed member")
	}
}

func TestVerifyReleaseArtifactsFailsWhenChecksumsMissingArchive(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		writeReleaseArchive(t, dist, name, releaseFilesForTest(name, binary))
	}
	writeChecksums(t, dist, "lsec_0.1.0_linux_amd64.tar.gz")

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when checksums.txt missed an expected archive")
	}
}

func TestVerifyReleaseArtifactsFailsWhenChecksumsContainExtraArchive(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		writeReleaseArchive(t, dist, name, releaseFilesForTest(name, binary))
	}
	if err := os.WriteFile(filepath.Join(dist, "extra.tar.gz"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when checksums.txt contained an extra archive")
	}
}

func TestVerifyReleaseArtifactsValidatesManifestNamesBeforeRunningShasum(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeValidReleaseArchives(t, dist)
	if err := os.WriteFile(filepath.Join(dist, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  ../outside.tar.gz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	called := filepath.Join(t.TempDir(), "shasum-called")
	fakeShasum := "#!/usr/bin/env sh\nprintf called > \"$SHASUM_CALLED\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "shasum"), []byte(fakeShasum), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"DIST="+dist,
		"VERSION=0.1.0",
		"SHASUM_CALLED="+called,
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts accepted an unsafe checksum path")
	}
	if _, err := os.Stat(called); !os.IsNotExist(err) {
		t.Fatalf("verify-release-artifacts ran shasum before validating manifest names: %v", err)
	}
}

func TestVerifyReleaseArtifactsFailsWhenUnlistedArchiveExists(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeValidReleaseArchives(t, dist)
	if err := os.WriteFile(filepath.Join(dist, "unlisted.tar.gz"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, dist, "unlisted.tar.gz")

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when an unlisted archive existed in DIST")
	}
}

func TestVerifyReleaseArtifactsFailsWhenHiddenArchiveExists(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeValidReleaseArchives(t, dist)
	if err := os.WriteFile(filepath.Join(dist, ".hidden.tar.gz"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, dist, ".hidden.tar.gz")

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a hidden archive existed in DIST")
	}
}

func TestVerifyReleaseArtifactsFailsWhenUnixBinaryIsNotExecutable(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		modes := map[string]int64{}
		if target == "linux_amd64" {
			modes[name+"/"+binary] = 0o600
		}
		writeReleaseArchiveWithModes(t, dist, name, files, modes)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a Unix binary was not executable")
	}
}

func TestVerifyReleaseArtifactsFailsWhenOnlyOtherExecuteBitIsSet(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		modes := map[string]int64{}
		if target == "linux_amd64" {
			modes[name+"/"+binary] = 0o001
		}
		writeReleaseArchiveWithModes(t, dist, name, releaseFilesForTest(name, binary), modes)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a Unix binary lacked owner execute permission")
	}
}

func TestVerifyReleaseArtifactsFailsWhenUnixBinaryIsDirectory(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesWithLinuxAMD64BinaryEntry(t, dist, tar.Header{
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a Unix binary was a directory")
	}
}

func TestVerifyReleaseArtifactsFailsWhenUnixBinaryIsSymlink(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesWithLinuxAMD64BinaryEntry(t, dist, tar.Header{
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
		Linkname: "other",
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a Unix binary was a symlink")
	}
}

func TestVerifyReleaseArtifactsAllowsWindowsBinaryWithoutUnixExecutableBit(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		modes := map[string]int64{}
		if target == "windows_amd64" {
			modes[name+"/"+binary] = 0o600
		}
		writeReleaseArchiveWithModes(t, dist, name, files, modes)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify-release-artifacts rejected Windows .exe without Unix executable bit: %v\n%s", err, out)
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveVersionMismatchesExpected(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		version := "0.1.0\n"
		if target == "linux_arm64" {
			version = "0.2.0\n"
		}
		files := releaseFilesForTest(name, binary)
		files[name+"/VERSION"] = version
		writeReleaseArchive(t, dist, name, files)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when an archive VERSION mismatched")
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveVersionHasMultipleLines(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		if target == "linux_amd64" {
			files[name+"/VERSION"] = "0.1\n.0\n"
		}
		writeReleaseArchive(t, dist, name, files)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when VERSION contained multiple lines")
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveVersionIsNotNormalized(t *testing.T) {
	for _, version := range []string{"0.1.0", "0.1.0\r\n"} {
		t.Run(strings.ReplaceAll(version, "\r", "cr"), func(t *testing.T) {
			root := repoRootForTest(t)
			dist := t.TempDir()
			writeReleaseArchivesWithVersion(t, dist, "linux_amd64", version)
			writeChecksums(t, dist)

			cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
			if err := cmd.Run(); err == nil {
				t.Fatalf("verify-release-artifacts accepted non-normalized VERSION %q", version)
			}
		})
	}
}

func TestVerifyReleaseArtifactsRejectsInvalidVersionBeforeArchivePaths(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeValidReleaseArchives(t, dist)
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=1.2.3/evil")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("verify-release-artifacts accepted a path-shaped VERSION")
	}
	if !strings.Contains(string(out), "invalid version") {
		t.Fatalf("verify-release-artifacts did not report invalid version:\n%s", out)
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveIsSymlink(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeValidReleaseArchives(t, dist)
	archive := filepath.Join(dist, "lsec_0.1.0_linux_amd64.tar.gz")
	external := filepath.Join(t.TempDir(), "archive.tar.gz")
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(external, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, archive); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts accepted a symlink as a physical archive")
	}
}

func TestVerifyReleaseArtifactsFailsWhenDocsDirectoryMemberIsMissing(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		directories := []string{name + "/", name + "/docs/"}
		if target == "linux_amd64" {
			directories = directories[:1]
		}
		writeReleaseArchiveWithDirectories(t, dist, name, releaseFilesForTest(name, binary), directories)
	}
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts accepted an archive without its docs directory member")
	}
}

func TestVerifyReleaseArtifactsCleansTemporaryDirectoryWithSpaces(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeValidReleaseArchives(t, dist)
	writeChecksums(t, dist)
	tmpDir := filepath.Join(t.TempDir(), "temporary files")
	if err := os.Mkdir(tmpDir, 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0", "TMPDIR="+tmpDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify-release-artifacts failed with spaces in TMPDIR: %v\n%s", err, out)
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("verify-release-artifacts left temporary entries: %v", entries)
	}
}

func TestBuildReleaseRejectsCurrentDirectoryAsDist(t *testing.T) {
	root := repoRootForTest(t)
	sentinel := filepath.Join(root, "go.mod")
	before, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST=.", "LSEC_RELEASE_ALLOW_UNTAGGED=1", "VERSION=0.1.0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("build-release accepted DIST=.")
	}
	if !strings.Contains(string(out), "unsafe DIST") {
		t.Fatalf("build-release did not report unsafe DIST:\n%s", out)
	}
	after, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("build-release removed sentinel: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("build-release changed sentinel while rejecting DIST=.")
	}
}

func TestBuildReleaseRejectsUnsafeDistPaths(t *testing.T) {
	root := repoRootForTest(t)
	repoParent := filepath.Dir(root)
	for _, tc := range []struct {
		name string
		dist string
	}{
		{name: "root", dist: "/"},
		{name: "parent", dist: ".."},
		{name: "repo_root", dist: root},
		{name: "repo_parent", dist: repoParent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			fakeBin := filepath.Join(work, "bin")
			if err := os.Mkdir(fakeBin, 0o700); err != nil {
				t.Fatal(err)
			}
			goCalled := filepath.Join(work, "go-called")
			fakeGo := "#!/usr/bin/env sh\nprintf called > \"$GO_CALLED\"\nexit 1\n"
			if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte(fakeGo), 0o700); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
			cmd.Dir = root
			cmd.Env = append(os.Environ(),
				"DIST="+tc.dist,
				"GO_CALLED="+goCalled,
				"LSEC_RELEASE_ALLOW_UNTAGGED=1",
				"VERSION=0.1.0",
				"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("build-release accepted unsafe DIST %q", tc.dist)
			}
			if !strings.Contains(string(out), "unsafe DIST") {
				t.Fatalf("build-release rejected DIST %q without unsafe DIST message:\n%s", tc.dist, out)
			}
			if _, err := os.Stat(goCalled); !os.IsNotExist(err) {
				t.Fatalf("build-release ran go despite unsafe DIST %q: %v", tc.dist, err)
			}
		})
	}
}

func TestBuildReleaseRefusesExistingDistBeforeBuilding(t *testing.T) {
	root := repoRootForTest(t)
	work := t.TempDir()
	dist := filepath.Join(work, "dist")
	if err := os.Mkdir(dist, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(dist, "sentinel")
	if err := os.WriteFile(sentinel, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(work, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	goCalled := filepath.Join(work, "go-called")
	fakeGo := `#!/usr/bin/env sh
printf called > "$GO_CALLED"
exit 1
`
	if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte(fakeGo), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"DIST="+dist,
		"GO_CALLED="+goCalled,
		"LSEC_RELEASE_ALLOW_UNTAGGED=1",
		"VERSION=0.1.0",
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("build-release accepted an existing DIST")
	}
	if !strings.Contains(string(out), "refusing to overwrite existing DIST") {
		t.Fatalf("build-release did not report existing DIST refusal:\n%s", out)
	}
	if _, err := os.Stat(goCalled); !os.IsNotExist(err) {
		t.Fatalf("build-release ran go despite existing DIST: %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("build-release removed published DIST contents: %v", err)
	}
	if string(data) != "existing" {
		t.Fatalf("build-release changed published DIST contents: %q", data)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lsec-release.") {
			t.Fatalf("build-release left private staging directory %q", entry.Name())
		}
	}
}

func TestBuildReleaseBuildFailureLeavesAbsentDistAbsent(t *testing.T) {
	root := repoRootForTest(t)
	work := t.TempDir()
	dist := filepath.Join(work, "dist")
	fakeBin := filepath.Join(work, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte("#!/usr/bin/env sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"DIST="+dist,
		"LSEC_RELEASE_ALLOW_UNTAGGED=1",
		"VERSION=0.1.0",
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	if err := cmd.Run(); err == nil {
		t.Fatal("build-release succeeded when Go build failed")
	}
	if _, err := os.Stat(dist); !os.IsNotExist(err) {
		t.Fatalf("build-release created DIST after failed build: %v", err)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".lsec-release.") {
			t.Fatalf("build-release left private staging directory %q", entry.Name())
		}
	}
}

func TestBuildReleaseRejectsPathShapedVersionBeforeStaging(t *testing.T) {
	root := repoRootForTest(t)
	work := t.TempDir()
	distParent := filepath.Join(work, "publish")
	dist := filepath.Join(distParent, "dist")
	if err := os.MkdirAll(distParent, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(work, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte("#!/usr/bin/env sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"DIST="+dist,
		"LSEC_RELEASE_ALLOW_UNTAGGED=1",
		"VERSION=../../../../escaped/release",
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("build-release accepted a path-shaped VERSION")
	}
	if !strings.Contains(string(out), "invalid version") {
		t.Fatalf("build-release did not report invalid version:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(distParent, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("build-release created escaped staging path: %v", err)
	}
}

func TestBuildReleaseRejectsInvalidNormalizedVersions(t *testing.T) {
	root := repoRootForTest(t)
	for _, version := range []string{
		"1.2",
		"1.2.3 bad",
		"1.2.3/evil",
		"1.2.3\n4",
		"release-1.2.3",
	} {
		t.Run(strings.NewReplacer("\n", "newline", "/", "slash", " ", "space").Replace(version), func(t *testing.T) {
			cmd := exec.Command("sh", filepath.Join(root, "scripts", "build-release.sh"))
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "DIST="+filepath.Join(t.TempDir(), "dist"), "LSEC_RELEASE_ALLOW_UNTAGGED=1", "VERSION="+version)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("build-release accepted invalid VERSION %q", version)
			}
			if !strings.Contains(string(out), "invalid version") {
				t.Fatalf("build-release rejected VERSION %q without invalid version message:\n%s", version, out)
			}
		})
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveMissingTechnicalOverview(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesMissingPath(t, dist, "linux_amd64", "docs/technical-overview.md")
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when an archive was missing docs/technical-overview.md")
	}
}

func TestVerifyReleaseArtifactsFailsWhenArchiveMissingRoadmap(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesMissingPath(t, dist, "darwin_arm64", "docs/roadmap.md")
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when an archive was missing docs/roadmap.md")
	}
}

func TestVerifyReleaseArtifactsFailsWhenRequiredDocIsDirectory(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesWithRequiredEntry(t, dist, "linux_amd64", "docs/technical-overview.md", tar.Header{
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a required doc was a directory")
	}
}

func TestVerifyReleaseArtifactsFailsWhenRequiredDocIsSymlink(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesWithRequiredEntry(t, dist, "linux_amd64", "README.md", tar.Header{
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
		Linkname: "other",
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when a required doc was a symlink")
	}
}

func TestVerifyReleaseArtifactsFailsWhenWindowsBinaryIsDirectory(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesWithRequiredEntry(t, dist, "windows_amd64", "lsec.exe", tar.Header{
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when Windows lsec.exe was a directory")
	}
}

func TestVerifyReleaseArtifactsFailsWhenWindowsBinaryIsSymlink(t *testing.T) {
	root := repoRootForTest(t)
	dist := t.TempDir()
	writeReleaseArchivesWithRequiredEntry(t, dist, "windows_amd64", "lsec.exe", tar.Header{
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
		Linkname: "other",
	})
	writeChecksums(t, dist)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "verify-release-artifacts.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST="+dist, "VERSION=0.1.0")
	if err := cmd.Run(); err == nil {
		t.Fatal("verify-release-artifacts succeeded when Windows lsec.exe was a symlink")
	}
}

func releaseTargetsForTest() []string {
	return []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64"}
}

func releaseFilesForTest(name, binary string) map[string]string {
	files := map[string]string{
		name + "/README.md":                  "readme",
		name + "/VERSION":                    "0.1.0\n",
		name + "/docs/technical-overview.md": "technical overview",
		name + "/docs/roadmap.md":            "roadmap",
	}
	if binary != "" {
		files[name+"/"+binary] = "binary"
	}
	return files
}

func writeValidReleaseArchives(t *testing.T, dist string) {
	t.Helper()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		writeReleaseArchive(t, dist, name, releaseFilesForTest(name, binary))
	}
}

func writeReleaseArchivesMissingPath(t *testing.T, dist, missingTarget, missingPath string) {
	t.Helper()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		if target == missingTarget {
			delete(files, name+"/"+missingPath)
		}
		writeReleaseArchive(t, dist, name, files)
	}
}

func writeReleaseArchivesWithVersion(t *testing.T, dist, replacementTarget, version string) {
	t.Helper()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		if target == replacementTarget {
			files[name+"/VERSION"] = version
		}
		writeReleaseArchive(t, dist, name, files)
	}
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
	writeReleaseArchiveWithModes(t, dist, name, files, nil)
}

func writeReleaseArchivesWithLinuxAMD64BinaryEntry(t *testing.T, dist string, binaryHeader tar.Header) {
	t.Helper()
	writeReleaseArchivesWithRequiredEntry(t, dist, "linux_amd64", "lsec", binaryHeader)
}

func writeReleaseArchivesWithRequiredEntry(t *testing.T, dist, replacementTarget, replacementPath string, header tar.Header) {
	t.Helper()
	for _, target := range releaseTargetsForTest() {
		name := "lsec_0.1.0_" + target
		binary := "lsec"
		if target == "windows_amd64" {
			binary = "lsec.exe"
		}
		files := releaseFilesForTest(name, binary)
		if target != replacementTarget {
			writeReleaseArchive(t, dist, name, files)
			continue
		}
		fullPath := name + "/" + replacementPath
		delete(files, fullPath)
		header.Name = fullPath
		writeReleaseArchiveWithExtraHeaders(t, dist, name, files, []tar.Header{header})
	}
}

func writeReleaseArchiveWithModes(t *testing.T, dist, name string, files map[string]string, modes map[string]int64) {
	t.Helper()
	writeReleaseArchiveWithExtraHeadersAndModes(t, dist, name, files, nil, modes)
}

func writeReleaseArchiveWithExtraHeaders(t *testing.T, dist, name string, files map[string]string, headers []tar.Header) {
	t.Helper()
	writeReleaseArchiveWithExtraHeadersAndModes(t, dist, name, files, headers, nil)
}

func writeReleaseArchiveWithExtraHeadersAndModes(t *testing.T, dist, name string, files map[string]string, headers []tar.Header, modes map[string]int64) {
	t.Helper()
	writeReleaseArchiveWithDirectoriesAndOptions(t, dist, name, files, []string{name + "/", name + "/docs/"}, headers, modes)
}

func writeReleaseArchiveWithDirectories(t *testing.T, dist, name string, files map[string]string, directories []string) {
	t.Helper()
	writeReleaseArchiveWithDirectoriesAndOptions(t, dist, name, files, directories, nil, nil)
}

func writeReleaseArchiveWithDirectoriesAndOptions(t *testing.T, dist, name string, files map[string]string, directories []string, headers []tar.Header, modes map[string]int64) {
	t.Helper()
	f, err := os.Create(filepath.Join(dist, name+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for _, dir := range directories {
		if err := tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range files {
		hdr := &tar.Header{Name: path, Mode: 0o600, Size: int64(len(body))}
		if filepath.Base(path) == "lsec" || filepath.Base(path) == "lsec.exe" {
			hdr.Mode = 0o700
		}
		if mode, ok := modes[path]; ok {
			hdr.Mode = mode
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, hdr := range headers {
		if err := tw.WriteHeader(&hdr); err != nil {
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

func writeChecksums(t *testing.T, dist string, omit ...string) {
	t.Helper()
	omitted := map[string]bool{}
	for _, name := range omit {
		omitted[name] = true
	}
	entries, err := os.ReadDir(dist)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".gz" {
			continue
		}
		if omitted[entry.Name()] {
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
