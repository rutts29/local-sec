package lsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateTempWorkspaceUsesPrivateDirectoryAndExclusiveFiles(t *testing.T) {
	workspace, err := newPrivateTempWorkspace("lsec-test-")
	if err != nil {
		t.Fatal(err)
	}
	dir := workspace.dir
	t.Cleanup(workspace.remove)

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %o, want 700", info.Mode().Perm())
	}

	path, err := workspace.writeExclusive("request.json", []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
	body, err := workspace.readRegular("request.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "request" {
		t.Fatalf("file body = %q, want request", body)
	}
	if _, err := workspace.writeExclusive("request.json", []byte("overwrite")); err == nil {
		t.Fatal("exclusive write replaced an existing file")
	}
}

func TestPrivateTempWorkspaceRejectsSymlinkReadsAndWrites(t *testing.T) {
	workspace, err := newPrivateTempWorkspace("lsec-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(workspace.remove)

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace.dir, "result.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := workspace.writeExclusive("result.json", []byte("changed")); err == nil {
		t.Fatal("exclusive write followed a symlink")
	}
	if _, err := workspace.readRegular("result.json"); err == nil {
		t.Fatal("regular-file read accepted a symlink")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "unchanged" {
		t.Fatalf("symlink target = %q, want unchanged", body)
	}
}

func TestPrivateTempWorkspaceRemovalDeletesContents(t *testing.T) {
	workspace, err := newPrivateTempWorkspace("lsec-test-")
	if err != nil {
		t.Fatal(err)
	}
	dir := workspace.dir
	if _, err := workspace.writeExclusive("request.json", []byte("request")); err != nil {
		t.Fatal(err)
	}
	workspace.remove()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("workspace remains after remove: %v", err)
	}
}

func TestPrivateTempWorkspaceRejectsPathNames(t *testing.T) {
	workspace, err := newPrivateTempWorkspace("lsec-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(workspace.remove)

	for _, name := range []string{"", ".", "..", "nested/result.json"} {
		if _, err := workspace.path(name); err == nil {
			t.Errorf("path %q accepted", name)
		}
	}
}
