# Scanner Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/scanner`  
**Exports:** `ReportScanner` interface, `TrivyScanner`, `GrypeScanner`

---

## Purpose

The scanner package provides pluggable parsers for different vulnerability report formats. It detects format, parses tool-specific JSON, and converts to a unified `Vulnerability` representation.

**Inputs:** Trivy or Grype JSON reports  
**Output:** Slice of `generator.Vulnerability` structs

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Input: JSON Report                          │
│  (from Trivy, Grype, or other scanner)                         │
└─────────────────────────┬──────────────────────────────────────┘
                          │
                          ▼
                  ┌───────────────────┐
                  │ DetectFormat()    │ OR  Manual NewScanner(Type)
                  │ (Auto-detect)     │
                  └─────────┬─────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
        ▼                                       ▼
    ┌─────────────────┐               ┌──────────────────┐
    │ TrivyScanner    │               │ GrypeScanner     │
    │ - Parse Trivy   │               │ - Parse Grype    │
    │ - Extract BOM   │               │ - Extract BOM    │
    │ - Map sources   │               │ - Map sources    │
    └────────┬────────┘               └────────┬─────────┘
             │                                 │
             └──────────────────┬──────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Unified Vulnerability │
                    │ (common format)       │
                    └───────────────────────┘
```

---

## ReportScanner Interface

```go
type ReportScanner interface {
    // Parse reads and converts a scanner report to common Vulnerability format
    Parse(data []byte) ([]generator.Vulnerability, error)
    
    // Name returns the scanner name (e.g., "trivy", "grype")
    Name() string
}
```

**Design:** Accept interfaces, return structs. Generator doesn't care about scanner internals, just the unified output.

---

## Detection: `DetectFormat()`

```go
func DetectFormat(data []byte) (ReportScanner, error)
```

**How it works:**
1. Unmarshal JSON into generic map
2. Check discriminator fields:
   - `"matches"` field → Grype
   - `"Results"` field → Trivy
3. Return appropriate scanner or error

**Example:**
```go
scanner, err := DetectFormat(reportJSON)
// Returns &GrypeScanner{} or &TrivyScanner{}

vulns, err := scanner.Parse(reportJSON)
```

**Why this approach?**
- No filesystem needed
- Works with piped input
- Fast discrimination (single pass)
- User-friendly (no format flag needed)

---

## Scanner Type: `TrivyScanner`

### Location
`trivy_scanner.go`

### What it parses
Trivy JSON reports from:
```bash
trivy image python:3.11 --format json
trivy fs /path/to/repo --format json
trivy config /path/to/terraform --format json
```

### Trivy Report Structure (simplified)

```json
{
  "Results": [
    {
      "Target": "python:3.11",
      "Type": "library",
      "Misconfigurations": [],
      "Secrets": [],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1234",
          "PkgName": "openssl",
          "InstalledVersion": "1.1.1",
          "FixedVersion": "1.1.1w",
          "Title": "Buffer overflow in OpenSSL",
          "Description": "...",
          "Severity": "CRITICAL",
          "CVSS": {
            "nvd": { "V3Vector": "CVSS:3.1/...", "V3Score": 9.8 }
          },
          "References": [...],
          "DataSource": {
            "Name": "NVD",
            "URL": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
          }
        }
      ]
    }
  ]
}
```

### Parsing Logic

```go
func (t *TrivyScanner) Parse(data []byte) ([]generator.Vulnerability, error) {
    // 1. Unmarshal JSON
    var report trivytypes.Report
    
    // 2. Iterate Results → Vulnerabilities
    for _, result := range report.Results {
        for _, vuln := range result.Vulnerabilities {
            // 3. Extract fields
            v := generator.Vulnerability{
                VulnID:           vuln.VulnerabilityID,
                PkgName:          vuln.PkgName,
                InstalledVersion: vuln.InstalledVersion,
                FixedVersion:     vuln.FixedVersion,
                Title:            vuln.Title,
                Description:      vuln.Description,
                Severity:         string(vuln.Severity),
                BOMRef:           calculateBOMRef(result, vuln),
                SourceName:       "NVD",
                SourceURL:        "https://nvd.nist.gov/...",
            }
            vulns = append(vulns, v)
        }
    }
    
    return vulns, nil
}
```

### BOM-Ref Calculation

Trivy uses a specific format for CycloneDX BOM-Ref:
```
pkg:language/package@version?package-id=id
```

**Example:**
```
pkg:npm/express@4.18.1?package-id=8c3ff3dd-e8ca-4bcc-a2c0-080e2e3e3848
```

This is used to link Trivy's internal representation to CycloneDX format.

### Source Mapping

**Trivy sources:**
- `NVD` (National Vulnerability Database)
- Vendor-specific sources
- Extracted from `DataSource` field in Trivy report

**Mapping:**
```
DataSource.Name → SourceName
DataSource.URL  → SourceURL
```

---

## Scanner Type: `GrypeScanner`

### Location
`grype_scanner.go`

### What it parses
Grype JSON reports from:
```bash
grype python:3.11 --output json
grype dir:/path/to/repo --output json
grype sbom:sbom.json --output json
```

### Grype Report Structure (simplified)

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-1234",
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "namespace": "nvd",
        "severity": "critical",
        "urls": [...],
        "description": "...",
        "cvss": [
          {
            "vector": "CVSS:3.1/AV:N/AC:L/...",
            "metrics": { "BaseScore": 9.8 }
          }
        ]
      },
      "artifact": {
        "id": "8c3ff3dd-e8ca-4bcc-a2c0-080e2e3e3848",
        "name": "openssl",
        "version": "1.1.1",
        "type": "package",
        "language": "python"
      },
      "matchDetails": [
        {
          "type": "cpe-match",
          "found": { "cpeuri": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*" }
        }
      ]
    }
  ],
  "source": {
    "type": "image",
    "target": "python:3.11"
  }
}
```

### Parsing Logic

```go
func (g *GrypeScanner) Parse(data []byte) ([]generator.Vulnerability, error) {
    // 1. Unmarshal JSON
    var report grypeJSON.Report
    
    // 2. Iterate matches
    for _, match := range report.Matches {
        vuln := match.Vulnerability
        artifact := match.Artifact
        
        // 3. Extract fields
        v := generator.Vulnerability{
            VulnID:           vuln.ID,
            PkgName:          artifact.Name,
            InstalledVersion: artifact.Version,
            FixedVersion:     extractFixedVersion(match),
            Title:            vuln.ID,
            Description:      vuln.Description,
            Severity:         vuln.Severity,
            BOMRef:           artifact.ID,
            SourceName:       vuln.Namespace,
            SourceURL:        vuln.DataSource,
        }
        vulns = append(vulns, v)
    }
    
    return vulns, nil
}
```

### BOM-Ref
Grype provides `artifact.id` directly (UUID format).

### Source Mapping

**Grype sources:**
- `nvd` (National Vulnerability Database)
- `debian`, `ubuntu` (distro CVE databases)
- `rhel` (Red Hat)
- Others (from various sources)

**Mapping:**
```
vuln.Namespace  → SourceName
vuln.DataSource → SourceURL
```

---

## Type Enums

```go
type ScannerType string

const (
    ScannerTrivy ScannerType = "trivy"
    ScannerGrype ScannerType = "grype"
)
```

**Usage:**
```go
scanner, err := NewScanner(ScannerTrivy)
```

---

## Factory: `NewScanner()`

```go
func NewScanner(scannerType ScannerType) (ReportScanner, error)
```

**Use when:** You know the scanner type upfront.

**Example:**
```go
scanner, err := NewScanner(ScannerTrivy)
vulns, err := scanner.Parse(data)
```

**Advantage over DetectFormat:** Explicit scanner selection (useful for testing).

---

## Output: `Vulnerability`

```go
// From pkg/generator/generator.go
type Vulnerability struct {
    VulnID           string  // CVE-XXXX-YYYY
    PkgID            string  // Package identifier
    PkgName          string  // Package name
    InstalledVersion string  // Currently installed version
    FixedVersion     string  // Available fix version (may be empty)
    BOMRef           string  // CycloneDX BOM-Ref
    Title            string  // CVE title/summary
    Description      string  // Full description
    Severity         string  // NVD severity (CRITICAL/HIGH/MEDIUM/LOW)
    SourceName       string  // Source (NVD, vendor, etc.)
    SourceURL        string  // Link to source
}
```

**Design:** Unified format regardless of input scanner.

---

## Testing

### Test Files
- `trivy_scanner_test.go` — TrivyScanner tests
- `grype_scanner_test.go` — GrypeScanner tests
- `source_test.go` — Source mapping tests

### Test Approach
```go
func TestTrivyScanner_Parse(t *testing.T) {
    // Load fixture JSON
    data := loadFixture("testdata/trivy-report.json")
    
    scanner := &TrivyScanner{}
    vulns, err := scanner.Parse(data)
    
    // Assert expectations
    assert.NoError(t, err)
    assert.Equal(t, 5, len(vulns))
    assert.Equal(t, "CVE-2024-1234", vulns[0].VulnID)
}
```

### Test Data
Located in `cmd/vens/testdata/` and `examples/`:
- Real Trivy reports
- Real Grype reports
- Integration test fixtures

---

## Error Handling

**Pattern:** Return formatted error with context.

```go
if err := json.Unmarshal(data, &report); err != nil {
    return nil, fmt.Errorf("failed to unmarshal Trivy report: %w", err)
}
```

**Common errors:**
- Invalid JSON → `json.SyntaxError`
- Unknown format → `fmt.Errorf("unknown report format")`
- Missing required fields → Gracefully skip (log warning)

---

## Extensibility

### Add Support for Another Scanner

1. Create `newscan_scanner.go`
2. Implement `ReportScanner` interface:
   ```go
   type NewscanScanner struct {}
   func (n *NewscanScanner) Parse(data []byte) ([]Vulnerability, error)
   func (n *NewscanScanner) Name() string
   ```
3. Add detection logic to `DetectFormat()`:
   ```go
   if _, hasNewscanField := raw["newscan_key"]; hasNewscanField {
       return &NewscanScanner{}, nil
   }
   ```
4. Update `NewScanner()` to handle new type
5. Add tests: `newscan_scanner_test.go`

---

## Key Design Decisions

### 1. **Unified Vulnerability Format**
Why not pass scanner-specific objects to Generator?
- Generator doesn't depend on Trivy/Grype directly
- Easier to test (mock vulnerabilities)
- Easier to add new scanners
- Scanner logic isolated in one place

### 2. **Auto-Detection**
Why not require explicit `--input-format` flag?
- Better UX (one less thing to remember)
- Discriminator fields are unambiguous
- DetectFormat() is a single unmarshal pass (fast)
- Can still explicitly specify if needed

### 3. **BOM-Ref Preservation**
Why preserve Trivy's specific BOM-Ref calculation?
- Allows re-linking back to Trivy's internal graph
- CycloneDX standard compliance
- Needed for `vens enrich` to work correctly

### 4. **Source Mapping**
Why map sources to unified SourceName?
- Different scanners have different source databases
- OWASP scoring may factor in source reliability
- Preserves provenance in VEX document

---

## Performance

| Scanner | Typical CVEs | Parse Time |
|---------|--------------|-----------|
| Trivy | 10-500 | 10-100ms |
| Grype | 10-500 | 10-100ms |

**Note:** Dominated by JSON unmarshal, not parsing logic.

---

## See Also

- **[Generator Codemap](./generator.md)** — Invokes scanner and processes output
- **[CLI Codemap](./cli.md)** — Calls scanner from `vens generate`
- **CONTRIBUTING.md** — Testing standards
- **Makefile** — Test targets

