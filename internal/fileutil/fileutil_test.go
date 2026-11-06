package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDir0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := EnsureDir0700(dir); err != nil {
		t.Fatalf("EnsureDir0700: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %o, want 700", info.Mode().Perm())
	}
	if err := EnsureDir0700(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestWriteFile0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "file")
	if err := WriteFile0600(path, []byte("secret")); err != nil {
		t.Fatalf("WriteFile0600: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "secret" {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if err := WriteFile0600("", nil); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestAtomicWriteFile0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "atomic")
	if err := AtomicWriteFile0600(path, []byte("one")); err != nil {
		t.Fatalf("AtomicWriteFile0600: %v", err)
	}
	if err := AtomicWriteFile0600(path, []byte("two")); err != nil {
		t.Fatalf("AtomicWriteFile0600 overwrite: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "two" {
		t.Fatalf("data = %q", data)
	}
	if err := AtomicWriteFile0600("", nil); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestFileutilErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir0700(file); err == nil {
		t.Fatal("expected mkdir error")
	}
	child := filepath.Join(file, "child")
	if err := WriteFile0600(child, []byte("x")); err == nil {
		t.Fatal("expected write error")
	}
	if err := AtomicWriteFile0600(child, []byte("x")); err == nil {
		t.Fatal("expected atomic write error")
	}
}

func TestAtomicWriteRenameError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile0600(target, []byte("x")); err == nil {
		t.Fatal("expected rename error")
	}
}
