# VEX Enrichment Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/vexenricher`  
**CLI Command:** `vens enrich`

---

## Purpose

The VEX enricher applies OWASP scores from a generated VEX file back to the original Trivy scanner report. This allows users to see contextual scores alongside all the other Trivy metadata in their original report format.

**Input:** Original Trivy report + VEX file with OWASP scores  
**Output:** Enriched Trivy report with OWASP ratings embedded

---

## Problem It Solves

**User flow:**
```
1. Scan: trivy image python:3.11 --format json > report.json
   (contains Trivy's CVSS scores)

2. Score: vens generate --config-file config.yaml report.json output.vex.json
   (generates OWASP scores in separate VEX file)

3. Enrich: vens enrich --vex output.vex.json report.json > enriched.json
   (merges OWASP scores back into original report)

4. Use enriched.json in your CI/CD pipeline
   (now has both CVSS and contextual OWASP scores)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│        vens enrich Command (cmd/vens/commands)          │
│  - Load VEX file                                        │
│  - Load Trivy report                                    │
│  - Create VEXEnricher                                   │
│  - Enrich and output                                    │
└────────────────────┬────────────────────────────────────┘
                     │
      ┌──────────────▼──────────────┐
      │    VEXEnricher              │
      │ Loads VEX, extracts scores  │
      │ Maps: CVE ID → OWASP score  │
      └────────────┬─────────────────┘
                   │
      ┌────────────▼──────────────────────┐
      │   EnrichReport()                  │
      │ - Load Trivy JSON                 │
      │ - Match CVE IDs                   │
      │ - Add OWASP ratings               │
      │ - Return enriched report          │
      └───────────────────────────────────┘
```

---

## Core Types

### VEXEnricher

```go
type VEXEnricher struct {
    // Map of VulnerabilityID to OWASP Score
    OWASPScorePerVulnID map[string]float64
}
```

**Simple design:** Extract all OWASP scores from VEX during init, then use for fast O(1) lookup during enrichment.

### Initialization: `New()`

```go
func New(vexData []byte) (*VEXEnricher, error)
```

**What it does:**
1. Unmarshal VEX document from JSON
2. Iterate all vulnerabilities
3. Extract OWASP ratings by Vulnerability ID
4. Build map for fast lookup

**Example:**
```go
vexData, _ := os.ReadFile("output.vex.json")
enricher, _ := vexenricher.New(vexData)
// enricher.OWASPScorePerVulnID = {
//   "CVE-2024-1234": 47.2,
//   "CVE-2024-5678": 15.8,
//   ...
// }
```

### Enrichment: `EnrichReport()`

```go
func (e *VEXEnricher) EnrichReport(ctx context.Context, reportData []byte) (*trivytypes.Report, error)
```

**What it does:**
1. Unmarshal Trivy report from JSON
2. Iterate all results and vulnerabilities
3. Look up OWASP score by CVE ID
4. Add OWASP rating to each vulnerability
5. Return enriched report

**Example:**
```go
reportData, _ := os.ReadFile("report.json")
enrichedReport, _ := enricher.EnrichReport(ctx, reportData)

// enrichedReport.Results[0].Vulnerabilities[0].Ratings now includes OWASP score
```

---

## Data Flow: Detailed

### Input 1: VEX Document

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "ratings": [
        {
          "score": 47.2,
          "severity": "high",
          "method": "OWASP",
          "vector": "SL:7/M:7/..."
        }
      ]
    }
  ]
}
```

### Input 2: Trivy Report

```json
{
  "Results": [
    {
      "Target": "python:3.11",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1234",
          "PkgName": "openssl",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": { "V3Score": 9.8 }
          }
          // (no OWASP rating yet)
        }
      ]
    }
  ]
}
```

### Processing

```
1. Parse VEX
   → OWASPScorePerVulnID = {"CVE-2024-1234": 47.2}

2. Parse Trivy report

3. For each vulnerability:
   - VulnID = "CVE-2024-1234"
   - Look up: OWASPScorePerVulnID["CVE-2024-1234"] = 47.2
   - Create CycloneDX rating:
     {
       "score": 47.2,
       "severity": "high",
       "method": "OWASP",
       "vector": "SL:7/M:7/..."
     }
   - Add to vulnerability.Ratings

4. Output enriched report
```

### Output: Enriched Trivy Report

```json
{
  "Results": [
    {
      "Target": "python:3.11",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1234",
          "PkgName": "openssl",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": { "V3Score": 9.8 }
          },
          "Ratings": [  // ← NEW: OWASP rating added
            {
              "score": 47.2,
              "severity": "high",
              "method": "OWASP",
              "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:8/RD:8/NC:7/PV:8"
            }
          ]
        }
      ]
    }
  ]
}
```

---

## CLI Integration

### Command: `vens enrich`

**Location:** `cmd/vens/commands/enrich/enrich.go`

**Usage:**
```bash
vens enrich --vex output.vex.json INPUT OUTPUT
```

### Arguments
- `INPUT` — Original Trivy JSON report
- `OUTPUT` — Output file for enriched report

### Flags
- `--vex` (required) — Path to VEX file from `vens generate`
- `--debug` — Enable debug logging

### Implementation

```go
func action(cmd *cobra.Command, args []string) error {
    vexPath, _ := cmd.Flags().GetString("vex")
    inputPath := args[0]
    outputPath := args[1]
    
    // Load VEX
    vexData, err := os.ReadFile(vexPath)
    
    // Create enricher
    enricher, err := vexenricher.New(vexData)
    
    // Load Trivy report
    reportData, err := os.ReadFile(inputPath)
    
    // Enrich
    enrichedReport, err := enricher.EnrichReport(ctx, reportData)
    
    // Convert back to JSON
    output, err := json.MarshalIndent(enrichedReport, "", "  ")
    
    // Write
    err = os.WriteFile(outputPath, output, 0644)
    
    return nil
}
```

---

## Matching Strategy

### Vulnerability ID Matching

```go
// In EnrichReport()
for i := range report.Results {
    for j := range report.Results[i].Vulnerabilities {
        vuln := &report.Results[i].Vulnerabilities[j]
        
        // Look up by Vulnerability ID
        if score, ok := e.OWASPScorePerVulnID[vuln.VulnerabilityID]; ok {
            // Add rating to vulnerability
            rating := cyclonedx.VulnerabilityRating{
                Score:    &score,
                Severity: calculateSeverity(score),
                Method:   cyclonedx.ScoringMethodOWASP,
                Vector:   vectorStr, // From VEX
            }
            vuln.Ratings = append(vuln.Ratings, rating)
        }
    }
}
```

**Match key:** Vulnerability ID (CVE number)

**Why this approach?**
- Simple and reliable
- Same CVE has same OWASP score regardless of package
- Fast O(1) lookup
- No false matches

### Handling Duplicates

If the same CVE appears in multiple packages:

```go
// Original report
package A @ v1: CVE-2024-1234
package B @ v2: CVE-2024-1234

// After enrichment (same score for both)
package A @ v1: CVE-2024-1234 → OWASP: 47.2
package B @ v2: CVE-2024-1234 → OWASP: 47.2
```

**Note:** Both get the same OWASP score since the score is contextual to the application, not the package version.

---

## Severity Inference

```go
func calculateSeverity(score float64) string {
    if score < 5.4 {
        return "low"
    } else if score < 12.5 {
        return "medium"
    } else if score < 28.1 {
        return "high"
    } else {
        return "critical"
    }
}
```

Mirrors the OWASP package's severity logic.

---

## Error Handling

**Graceful degradation:**

If VEX lookup fails for a CVE:
- Log warning
- Continue processing
- That CVE's Trivy data unchanged (no OWASP rating)

**Pattern:**
```go
enrichedCount := 0
for _, vuln := range report.Results[i].Vulnerabilities {
    if score, ok := e.OWASPScorePerVulnID[vuln.VulnerabilityID]; ok {
        // Add rating
        enrichedCount++
    }
}
slog.InfoContext(ctx, "Enrichment complete",
    "enriched_count", enrichedCount,
    "total_vulns", len(report.Results[i].Vulnerabilities),
)
```

---

## Testing

### Unit Tests: `enricher_test.go`

```go
func TestEnricher_EnrichReport(t *testing.T) {
    vexData := []byte(`{
        "vulnerabilities": [{
            "id": "CVE-2024-1234",
            "ratings": [{
                "score": 47.2,
                "method": "OWASP"
            }]
        }]
    }`)
    
    enricher, _ := New(vexData)
    
    reportData := []byte(`{
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-1234"
            }]
        }]
    }`)
    
    report, _ := enricher.EnrichReport(ctx, reportData)
    
    assert.Equal(t, 1, len(*report.Results[0].Vulnerabilities[0].Ratings))
    assert.Equal(t, 47.2, *report.Results[0].Vulnerabilities[0].Ratings[0].Score)
}
```

### Integration Tests

In `cmd/vens/testdata/script/`:
```bash
# Generate VEX
exec vens generate --config-file config.yaml --llm mock report.json output.vex.json

# Enrich original report
exec vens enrich --vex output.vex.json report.json enriched.json

# Verify enrichment
exec jq '.Results[0].Vulnerabilities[0].Ratings[0].method' enriched.json
stdout OWASP
```

---

## Use Cases

### 1. Security Dashboard Integration

```python
# Load enriched report
report = json.load(open("enriched.json"))

# Group by OWASP severity
critical = [v for v in vulns if v.get("Ratings", [{}])[0].get("severity") == "critical"]
high = [...]

# Display in dashboard
```

### 2. Policy Enforcement

```yaml
# Policy: only CVSS HIGH/CRITICAL are actionable if OWASP score < 20
- name: "Reduce noise with contextual scoring"
  condition: |
    cvss_severity in ["HIGH", "CRITICAL"] AND
    owasp_score < 20.0
  action: "suppress"
```

### 3. SLA-Based Remediation

```yaml
# OWASP CRITICAL (>28) must be fixed within 24h
# OWASP HIGH must be fixed within 1 week
fix_deadlines:
  critical: "24h"
  high: "1w"
  medium: "1m"
  low: "ignored"
```

---

## Performance

| Operation | Complexity |
|-----------|-----------|
| Load VEX | O(n) where n = vulns in VEX |
| Build score map | O(n) |
| Enrich report | O(m × O(1)) = O(m) where m = vulns in report |
| JSON serialize | O(m) |

**Typical performance (100 CVEs):**
- Load VEX: ~10ms
- Enrich: ~5ms
- Serialize: ~10ms
- **Total: ~25ms**

---

## Limitations

1. **Simple ID matching** — Doesn't handle:
   - Different CPE formats
   - Package version variations
   - Transitive dependencies

2. **Overwrites existing OWASP ratings** — If Trivy report already has OWASP ratings, they're replaced

3. **No source reconciliation** — Assumes same CVE ID means same vulnerability

**Future enhancements:**
- Package-version-aware matching
- Merge instead of replace ratings
- Cross-check sources

---

## See Also

- **[CLI Codemap](./cli.md)** — Enrich command integration
- **[VEX Generation Codemap](./output.md)** — Source of VEX files
- **[Generator Codemap](./generator.md)** — How OWASP scores are created
- **CONTRIBUTING.md** — Testing standards

