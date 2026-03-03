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

package sbom

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// CalculateBOMRef calculates the BOM-Ref using Trivy's logic.
// This follows the same algorithm as Trivy to ensure VEX compatibility.
//
// Logic (from Trivy pkg/sbom/core/bom.go):
//  1. If BOMRef is already set, use it
//  2. If no PURL, use fallback identifier (PkgID)
//  3. If PURL is not unique (appears multiple times), use fallback identifier
//  4. Otherwise, use PURL
//
// See: https://github.com/aquasecurity/trivy/blob/main/pkg/sbom/core/bom.go#L364
func CalculateBOMRef(pkgID ftypes.PkgIdentifier, fallbackID string, purlCounts map[string]int) string {
	// 1. If BOMRef is already set, use it
	if pkgID.BOMRef != "" {
		return pkgID.BOMRef
	}

	// 2. If no PURL, use fallback identifier
	if pkgID.PURL == nil {
		return fallbackID
	}

	purl := pkgID.PURL.ToString()

	// 3. If PURL is not unique (appears multiple times), use fallback identifier
	if purlCounts[purl] > 1 {
		return fallbackID
	}

	// 4. Otherwise, use PURL
	return purl
}
