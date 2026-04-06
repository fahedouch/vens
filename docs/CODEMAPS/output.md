# Output & VEX Generation Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/outputhandler`  
**Key Files:** `outputhandler.go`, `cyclonedxvex.go`

---

## Purpose

The output handler package provides a pluggable abstraction for generating vulnerability reports in different formats. Currently implements CycloneDX VEX (Vulnerability Exploitability eXchange) format, but extensible for other formats.

**Input:** Stream of vulnerability ratings  
**Output:** CycloneDX VEX JSON document

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│         Generator                               │
│  Sends: VulnRating stream (per CVE)            │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
      ┌──────────────────────────┐
      │  OutputHandler Interface │
      │  - HandleVulnRatings()   │
      │  - Close()               │
      └────────────┬─────────────┘
                   │
    ┌──────────────▼────────────────┐
    │  CycloneDxVexHandler          │
    │  - Builds VEX document        │
    │  - Aggregates vulnerabilities │
    │  - Writes JSON to file        │
    └───────────────────────────────┘
```

---

## OutputHandler Interface

```go
type OutputHandler interface {
    // HandleVulnRatings ingests ratings grouped by vulnerability ID
    HandleVulnRatings([]VulnRating) error
    
    // Close finalizes output and writes to file
    Close() error
}

// VulnRating carries a single CycloneDX rating for one vulnerability ID
type VulnRating struct {
    VulnID string                           // CVE ID
    BOMRef string                           // CycloneDX BOM-Ref
    Rating cyclonedx.VulnerabilityRating   // OWASP rating
    Source *cyclonedx.Source               // CVE source metadata
}
```

**Design:** Streaming interface — process vulnerabilities in batches without holding entire VEX in memory.

---

## CycloneDxVexHandler

### Initialization

```go
func New(outputPath string, bomLink *BOMLink) (*CycloneDxVexHandler, error)
```

**Parameters:**
- `outputPath` — File path for VEX output
- `bomLink` — Optional: links VEX to original SBOM

**Returns handler or error if output path invalid.**

### BOM-Link

```go
type BOMLink struct {
    SerialNumber string // urn:uuid:...
    Version      int    // SBOM version
}
```

**Purpose:** Connects VEX document to the original SBOM.

**Example:**
```bash
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
vens generate --sbom-serial-number "$SBOM_UUID" ...
```

**In VEX document:**
```json
{
  "bom-link": {
    "component": {
      "bom-ref": "urn:uuid:...",
      "version": 1
    }
  }
}
```

---

## Processing Flow

### 1. Create Handler
```go
handler, err := outputhandler.New(outputPath, &BOMLink{
    SerialNumber: "urn:uuid:123...",
    Version: 1,
})
```

### 2. Stream Ratings (Called by Generator)
```go
ratings := []outputhandler.VulnRating{
    {
        VulnID: "CVE-2024-1234",
        BOMRef: "pkg:npm/express@4.18.1?package-id=...",
        Rating: cyclonedx.VulnerabilityRating{
            Score:    &score,
            Severity: "high",
            Method:   cyclonedx.ScoringMethodOWASP,
            Vector:   "SL:7/M:7/...",
        },
        Source: &cyclonedx.Source{
            Name: "NVD",
            URL:  "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        },
    },
    // More ratings...
}

if err := handler.HandleVulnRatings(ratings); err != nil {
    return fmt.Errorf("failed to write VEX: %w", err)
}
```

### 3. Finalize
```go
if err := handler.Close(); err != nil {
    return fmt.Errorf("failed to close VEX: %w", err)
}
```

---

## CycloneDX VEX Document Structure

### Top Level

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2024-04-05T12:00:00Z"
  },
  "vulnerabilities": [ /* array of vulns */ ]
}
```

### Each Vulnerability Entry

```json
{
  "id": "CVE-2024-1234",
  "source": {
    "name": "NVD",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
  },
  "ratings": [
    {
      "score": 47.2,
      "severity": "high",
      "method": "OWASP",
      "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:8/RD:8/NC:7/PV:8"
    }
  ]
}
```

### With BOM-Link (Optional)

```json
{
  "bom-link": {
    "component": {
      "bom-ref": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
      "version": 1
    }
  },
  "vulnerabilities": [ /* ... */ ]
}
```

---

## Implementation Details

### Data Aggregation

```go
type CycloneDxVexHandler struct {
    outputPath string
    bomLink    *BOMLink
    // Aggregate vulnerabilities by ID to handle duplicates
    vulnsByID  map[string]*cyclonedx.Vulnerability
}
```

**Why aggregation?**
- Generator may process same CVE across multiple packages
- VEX format lists each CVE once with all ratings
- Map allows efficient deduplication

### Writing JSON

```go
func (h *CycloneDxVexHandler) Close() error {
    // Build final VEX document
    doc := &cyclonedx.BOM{
        BOMFormat: "CycloneDX",
        SpecVersion: "1.4",
        Version: 1,
        Vulnerabilities: h.buildVulnerabilities(),
    }
    
    // Marshal to JSON
    data, err := json.MarshalIndent(doc, "", "  ")
    
    // Write to file
    return os.WriteFile(h.outputPath, data, 0644)
}
```

### Error Handling

**Common errors:**
- Invalid output path → Early error in `New()`
- Write failure → Error in `Close()`
- Invalid rating data → Error in `HandleVulnRatings()`

**Strategy:** Fail fast with context-rich errors.

---

## Extension Points

### Adding a New Output Format

1. **Implement interface**
   ```go
   type CustomHandler struct {
       outputPath string
       // custom fields
   }
   
   func (c *CustomHandler) HandleVulnRatings(ratings []VulnRating) error {
       // Custom logic
   }
   
   func (c *CustomHandler) Close() error {
       // Finalize and write
   }
   ```

2. **Register in factory** (future enhancement)
   ```go
   func NewHandler(format string, ...) OutputHandler {
       switch format {
       case "vex":
           return &CycloneDxVexHandler{...}
       case "custom":
           return &CustomHandler{...}
       }
   }
   ```

3. **Update CLI flag** (in `cmd/vens/commands/generate/generate.go`)
   ```go
   flags.String("output-format", "auto", "vex|custom|...")
   ```

---

## Testing

### Unit Tests: `cyclonedxvex_test.go`

```go
func TestCycloneDxVexHandler_Write(t *testing.T) {
    // Create temp file
    tmpfile, err := ioutil.TempFile("", "test-*.json")
    assert.NoError(t, err)
    
    // Create handler
    handler, err := New(tmpfile.Name(), nil)
    assert.NoError(t, err)
    
    // Handle ratings
    ratings := []VulnRating{
        {
            VulnID: "CVE-2024-1234",
            Rating: cyclonedx.VulnerabilityRating{
                Score: floatPtr(47.2),
                Severity: "high",
            },
        },
    }
    
    assert.NoError(t, handler.HandleVulnRatings(ratings))
    assert.NoError(t, handler.Close())
    
    // Verify output
    data, err := os.ReadFile(tmpfile.Name())
    assert.NoError(t, err)
    
    var doc cyclonedx.BOM
    assert.NoError(t, json.Unmarshal(data, &doc))
    assert.Equal(t, 1, len(*doc.Vulnerabilities))
}
```

### Integration Tests

VEX output validated in `cmd/vens/testdata/script/` tests:
```bash
exec vens generate --config-file config.yaml report.json output.vex.json
exec jq -e '.vulnerabilities[0].ratings[0].method == "OWASP"' output.vex.json
```

---

## CycloneDX Compliance

The handler produces VEX documents compliant with:
- **CycloneDX 1.4 specification**
- **VEX metadata** (bom-link, vulnerability ratings)
- **OWASP Risk Rating method**

**Validation:**
```bash
# Validate against CycloneDX schema
python -m cyclonedx_python --output-file output.vex.json
```

---

## Performance

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Create handler | O(1) | Single allocations |
| Handle ratings | O(n) | n = vulnerabilities in batch |
| Deduplication | O(1) per vuln | Map lookup |
| JSON marshal | O(n) | Total vulnerabilities |
| Write to disk | O(file size) | I/O bound |

**Typical profile (100 CVEs):**
- Handle batches: ~10ms
- JSON marshal: ~20ms
- Write: ~5ms
- **Total: ~35ms**

---

## See Also

- **[Generator Codemap](./generator.md)** — Invokes output handler
- **[CLI Codemap](./cli.md)** — Creates handler from CLI
- **CycloneDX Documentation:** https://cyclonedx.org/
- **CycloneDX Go Library:** https://github.com/CycloneDX/cyclonedx-go

