// Copyright 2025 venslabs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package generate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputFileModePreservesExistingPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fi.Mode().Perm()
	if got := outputFileMode(path); got != want {
		t.Fatalf("outputFileMode(%q) = %04o, want %04o", path, got, want)
	}
}

func TestOutputFileModeMissingMatchesOsCreate(t *testing.T) {
	dir := t.TempDir()
	createdPath := filepath.Join(dir, "created")
	f, err := os.Create(createdPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(createdPath)
	if err != nil {
		t.Fatal(err)
	}
	want := fi.Mode().Perm()
	got := outputFileMode(filepath.Join(dir, "missing.json"))
	if got != want {
		t.Fatalf("outputFileMode(missing) = %04o, want %04o (os.Create default)", got, want)
	}
}

func TestTempOutputFileUsesOutputFileMode(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "report.json")
	tmp, err := tempOutputFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(name) })

	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	want := outputFileMode(dest)
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("temp file mode = %04o, want %04o", got, want)
	}
}
