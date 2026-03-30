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

// Output handler pattern inspired by github.com/AkihiroSuda/vexllm/pkg/outputhandler

package outputhandler

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

type OutputHandler interface {
	// HandleVulnRatings ingests ratings grouped by vulnerability ID (e.g., CVE).
	HandleVulnRatings([]VulnRating) error
	Close() error
}

// VulnRating carries a single CycloneDX rating for one vulnerability ID.
type VulnRating struct {
	VulnID string
	BOMRef string // CycloneDX BOM-Ref (calculated using Trivy's logic)
	Rating cyclonedx.VulnerabilityRating
	Source *cyclonedx.Source // Vulnerability source (e.g., NVD, GHSA, OSV)
}

// VulnSource derives a CycloneDX Source from a vulnerability ID prefix.
// This is used as a fallback when the scanner does not provide source metadata.
// It maps well-known prefixes to their respective databases. Unknown prefixes
// return "UNKNOWN" which is accepted by Dependency-Track but will only match
// vulnerabilities stored with the same source.
func VulnSource(vulnID string) *cyclonedx.Source {
	switch {
	case strings.HasPrefix(vulnID, "CVE-"):
		return &cyclonedx.Source{
			Name: "NVD",
			URL:  "https://nvd.nist.gov/vuln/detail/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "GHSA-"):
		return &cyclonedx.Source{
			Name: "GITHUB",
			URL:  "https://github.com/advisories/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "GO-"):
		return &cyclonedx.Source{
			Name: "OSV",
			URL:  "https://osv.dev/vulnerability/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "PYSEC-"):
		return &cyclonedx.Source{
			Name: "OSV",
			URL:  "https://osv.dev/vulnerability/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "RUSTSEC-"):
		return &cyclonedx.Source{
			Name: "OSV",
			URL:  "https://osv.dev/vulnerability/" + vulnID,
		}
	default:
		return &cyclonedx.Source{
			Name: "UNKNOWN",
		}
	}
}
