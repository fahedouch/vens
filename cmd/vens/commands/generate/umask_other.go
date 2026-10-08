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

//go:build !unix

package generate

import "os"

// outputFileMode reports the permissions the output file should have: the
// destination's existing mode when it already exists, otherwise 0666, which
// is what os.Create produces on platforms with no umask (Windows).
func outputFileMode(outputPath string) os.FileMode {
	if fi, err := os.Stat(outputPath); err == nil {
		return fi.Mode().Perm()
	}
	return 0o666
}
