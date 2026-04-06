# Generator Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/generator`  
**Entry Points:** `Generate()`, `GenerateFromVulnerabilities()`

---

## Purpose

The Generator is the core of vens. It transforms scanner vulnerability reports into OWASP risk-scored CycloneDX VEX documents using LLM intelligence.

**Input:** Trivy or Grype JSON report + config.yaml  
**Output:** CycloneDX VEX document with OWASP ratings

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Generator                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Input Phase                                         │   │
│  │ - Parse scanner report (via Scanner interface)      │   │
│  │ - Extract vulnerabilities to common format         │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │ Processing Phase                                    │   │
│  │ - Batch vulnerabilities                             │   │
│  │ - Format as LLMVulnerability structs                │   │
│  │ - Generate system prompt from config.yaml           │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │ LLM Phase (per batch)                               │   │
│  │ - Call LLM with structured JSON Schema              │   │
│  │ - Parse response: [VulnID, scores for 4 factors]    │   │
│  │ - Handle rate limits (429) with exponential backoff │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │ Scoring Phase (per vulnerability)                   │   │
│  │ - Build OWASP Risk Rating vector (16 factors)       │   │
│  │ - Calculate final score: Risk = Likelihood × Impact │   │
│  │ - Classify severity (LOW < MEDIUM < HIGH < CRITICAL)│   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │ Output Phase                                        │   │
│  │ - Create VulnRating with CycloneDX Rating object    │   │
│  │ - Pass to OutputHandler                             │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Types

### Input: `Vulnerability`

```go
type Vulnerability struct {
    VulnID           string  // CVE-XXXX-YYYY
    PkgID            string  // Package identifier
    PkgName          string  // Package name
    InstalledVersion string  // Currently installed version
    FixedVersion     string  // Available fix version
    BOMRef           string  // CycloneDX BOM-Ref (Trivy format)
    Title            string  // CVE title/summary
    Description      string  // Full description
    Severity         string  // NVD severity (CRITICAL/HIGH/MEDIUM/LOW)
    SourceName       string  // Source (NVD, vendor, etc.)
    SourceURL        string  // Link to source
}
```

**Purpose:** Unified representation after scanner-specific parsing.

### LLM Communication: `LLMVulnerability`

```go
type LLMVulnerability struct {
    VulnID           string  // CVE ID
    PkgID            string  // Package identifier
    PkgName          string  // Package name
    InstalledVersion string  // Currently installed version
    FixedVersion     string  // Available fix version
    Title            string  // CVE title
    Description      string  // Full description
    Severity         string  // CVSS severity (for context)
}
```

**Purpose:** Lightweight payload sent to LLM to minimize tokens.

### LLM Response: `llmOutputEntry`

```go
type llmOutputEntry struct {
    VulnID             string  // CVE ID
    ThreatAgentScore   float64 // 0-9: Threat actor factors
    VulnFactorScore    float64 // 0-9: Vulnerability ease factors
    TechnicalImpact    float64 // 0-9: System impact factors
    BusinessImpact     float64 // 0-9: Business/compliance impact
    Reasoning          string  // LLM explanation
}
```

**Purpose:** Structured LLM response with reasoning.

### Output: `VulnRating`

```go
type VulnRating struct {
    VulnID string                           // CVE ID
    BOMRef string                           // CycloneDX reference
    Rating cyclonedx.VulnerabilityRating   // OWASP rating
    Source *cyclonedx.Source               // CVE source metadata
}
```

**Purpose:** Ready for OutputHandler to write to VEX document.

---

## Main Functions

### `Generate()`

```go
func Generate(ctx context.Context, opts ...Option) ([]byte, error)
```

**What it does:**
1. Parse input report (Trivy/Grype auto-detect)
2. Extract vulnerabilities
3. Load config.yaml context
4. Select LLM provider
5. Process vulnerabilities in batches
6. Generate VEX output
7. Save debug data (optional)

**Options pattern:**
```go
Generate(ctx,
    WithInputReport(reportData),
    WithConfig(configData),
    WithLLM(llmProvider),
    WithDebugDir("/tmp/debug"),
    WithBatchSize(10),
    WithOutputHandler(vexHandler),
)
```

### `GenerateFromVulnerabilities()`

```go
func GenerateFromVulnerabilities(ctx context.Context, vulns []Vulnerability, 
    llmAPI llms.Model, config *riskconfig.Config, 
    opts ...Option) error
```

**What it does:**
- Lower-level entry point (already parsed vulnerabilities)
- Batches vulnerabilities
- Calls LLM for scoring
- Generates VEX entries
- Feeds to OutputHandler

**Use case:** When you have vulnerabilities already parsed from a different source.

---

## LLM Integration

### System Prompt Construction

**Pattern from config.yaml:**
```yaml
project:
  name: "my-api"
  description: "Customer-facing REST API"
context:
  exposure: "internet"
  data_sensitivity: "high"
  business_criticality: "critical"
  compliance_requirements: ["GDPR", "PCI-DSS"]
  controls:
    waf: true
    authentication: "mfa"
```

**Becomes system prompt:**
```
You are a vulnerability risk assessment expert using the OWASP Risk Rating 
methodology. Assess this CVE in the context of:

- Exposure: internet-facing
- Data sensitivity: high (customer PII)
- Business criticality: critical
- Compliance: GDPR, PCI-DSS
- Controls: WAF enabled, MFA required

Calculate scores for each OWASP factor (0-9 scale):
1. Threat Agent (skill, motive, opportunity, size)
2. Vulnerability (ease of discovery, exploit, awareness, detection)
3. Technical Impact (confidentiality, integrity, availability, accountability)
4. Business Impact (financial damage, reputation, compliance, privacy)
```

### JSON Schema

LLM must respond with this schema:

```json
{
  "type": "object",
  "properties": {
    "vulnId": { "type": "string" },
    "threatAgentScore": { "type": "number" },
    "vulnFactorScore": { "type": "number" },
    "technicalImpact": { "type": "number" },
    "businessImpact": { "type": "number" },
    "reasoning": { "type": "string" }
  },
  "required": [...]
}
```

### Batch Processing

**Default:** 10 CVEs per request  
**Configurable:** `--llm-batch-size N`

**Why batching?**
- Reduces token overhead (single prompt, shared context)
- Faster processing
- Better cost efficiency
- Easier to handle rate limits

### Rate Limit Handling

```go
func RetryOnRateLimit(ctx context.Context, interval time.Duration, 
    maxRetry int, fn func(context.Context) error) error
```

**Strategy:**
1. Detect HTTP 429 or provider rate-limit errors
2. Sleep for configurable interval (default: 10s)
3. Retry up to maxRetry times (default: 10)
4. Return error if still failing after all retries

---

## Risk Calculation Pipeline

### Step 1: Build OWASP Vector

From 4 LLM scores, construct 16-factor OWASP Risk Rating vector:

```go
func FromAggregatedScores(threatAgent, vulnerability, technicalImpact, businessImpact float64) *OwaspRRVector
```

**Distribution logic:**
- ThreatAgent (0-9) → SL, M, O, S (each gets the same value)
- Vulnerability (0-9) → ED, EE, A, ID (each gets the same value)
- TechnicalImpact (0-9) → LC, LI, LAV, LAC (each gets the same value)
- BusinessImpact (0-9) → FD, RD, NC, PV (each gets the same value)

**Example vector:**
```
SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:7/RD:7/NC:6/PV:9
```

### Step 2: Calculate Risk Score

```
Risk = Likelihood × Impact (0-81 scale)

Where:
  Likelihood = (ThreatAgent + Vulnerability) / 2
  Impact = (TechnicalImpact + BusinessImpact) / 2
```

**Example:**
- ThreatAgent: 7, Vulnerability: 6 → Likelihood = 6.5
- TechnicalImpact: 8, BusinessImpact: 7 → Impact = 7.5
- Risk = 6.5 × 7.5 = 48.75

### Step 3: Classify Severity

```
[0.1, 5.4)   → LOW
[5.4, 12.5)  → MEDIUM
[12.5, 28.1) → HIGH
[28.1, 81]   → CRITICAL
```

**Note:** Thresholds can be customized via config.

---

## Output Handler Integration

Generator doesn't write files directly. Instead, it streams ratings through an `OutputHandler`:

```go
type OutputHandler interface {
    HandleVulnRatings([]VulnRating) error
    Close() error
}
```

**Default:** CycloneDX VEX handler in `pkg/outputhandler/cyclonedxvex.go`

**Pattern:** This allows plugging in different outputs (JSON, SBOM, metrics, etc.) without modifying Generator.

---

## Debug Mode

When `--debug-dir <path>` is set:

**Saved files:**
- `prompts.jsonl` — System prompt + each batch request
- `responses.jsonl` — Full LLM responses
- `parsed_output.json` — After LLM parsing
- `risk_calculations.json` — Scores and vectors
- `timing.json` — Performance metrics

**Purpose:** Troubleshooting and auditing LLM decisions.

---

## Testing

### Unit Tests: `generator_test.go`

- Vulnerability parsing
- Batch formation
- Score calculation
- OWASP vector construction

### Integration Tests: `cmd/vens/testdata/script/`

- End-to-end `vens generate` command
- Mock LLM responses
- VEX output validation
- Config parsing

---

## Key Design Decisions

### 1. **4-Factor Aggregation**
Why not all 16 OWASP factors?
- LLM token efficiency (fewer factors to score)
- Simpler prompt engineering
- Mathematically equivalent (can expand to 16-factor vector)
- Still produces valid OWASP RR vectors

### 2. **Batching**
Why not score one CVE at a time?
- Cost: 1/10th the API calls
- Speed: Multiple CVEs in single LLM roundtrip
- Context: LLM can calibrate scores across batch

### 3. **JSON Schema Enforcement**
Why strict schema?
- Prevents hallucination
- Guarantees parseable output
- No regex parsing needed
- langchaingo supports JSON Schema (via custom fork)

### 4. **Mock LLM**
Why built-in mock?
- Test without API credentials
- Deterministic output
- Fast integration tests
- CI/CD friendly

---

## Common Patterns in Code

### 1. Context Propagation
```go
func (g *Generator) process(ctx context.Context) error {
    // Always accept ctx as first parameter for potential cancellation/timeout
}
```

### 2. Error Wrapping
```go
if err := someFunc(); err != nil {
    return fmt.Errorf("context of what failed: %w", err)
}
```

### 3. Functional Options
```go
type Option func(*Generator)

func WithBatchSize(size int) Option {
    return func(g *Generator) { g.batchSize = size }
}
```

---

## Extension Points

### Add a New LLM Provider

1. Implement `llms.Model` interface from langchaingo
2. Register in `pkg/llm/llmfactory/`
3. Update README environment variables

### Modify Risk Calculation

1. Edit vector distribution in `FromAggregatedScores()`
2. Update thresholds in severity classification
3. Update tests and documentation

### Add Debug Output

1. Add new field to debug structure
2. Write to `--debug-dir` in Close()
3. Document in CONTRIBUTING.md

---

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Parse report | O(n) | n = vulnerabilities |
| Load config | O(1) | Small YAML file |
| Batch formation | O(n) | Linear pass through vulns |
| LLM call | O(b × tokens) | b = batch size, token-based billing |
| Score calculation | O(n) | Simple arithmetic per vulnerability |
| VEX generation | O(n) | Linear write through handler |

**Typical perf for 100 CVEs (batch size 10):**
- Parse: ~50ms
- LLM: ~10-30s (network bound)
- Scoring: ~100ms
- Total: ~10-30s (dominated by LLM latency)

---

## See Also

- **[LLM Codemap](./llm.md)** — LLM provider details
- **[Scanner Codemap](./scanner.md)** — Input format parsing
- **[OWASP Codemap](./owasp.md)** — Risk calculation formulas
- **[Output Codemap](./output.md)** — VEX document generation
- **CONTRIBUTING.md** — Testing and code standards

