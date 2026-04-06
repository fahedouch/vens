# Configuration Management Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/riskconfig`  
**User File:** `config.yaml` (root level)

---

## Purpose

The configuration system allows users to describe their application context (exposure, data sensitivity, compliance requirements, controls) in a simple YAML file. This context is used by the LLM to calculate contextual OWASP risk scores.

**Input:** `config.yaml` file  
**Output:** Validated `Config` struct for use by Generator

---

## Architecture

```
┌──────────────────────────────────┐
│    config.yaml (user file)       │
└────────────┬─────────────────────┘
             │
             ▼
┌──────────────────────────────────┐
│   Config Parser                  │
│   - Load YAML                    │
│   - Validate schema              │
│   - Set defaults                 │
└────────────┬─────────────────────┘
             │
             ▼
┌──────────────────────────────────┐
│    Config Struct                 │
│    - Project metadata            │
│    - Context factors             │
│    - Compliance requirements     │
│    - Controls                    │
└──────────────────────────────────┘
```

---

## Config Struct

### Full Definition

```go
type Config struct {
    Project struct {
        Name        string
        Description string
    }
    
    Context struct {
        Exposure              string   // "internal" | "private" | "internet"
        DataSensitivity       string   // "low" | "medium" | "high" | "critical"
        BusinessCriticality   string   // "low" | "medium" | "high" | "critical"
        ComplianceRequirements []string // "GDPR", "PCI-DSS", "HIPAA", etc.
        Notes                 string   // Free-form context
        
        Controls struct {
            WAF                bool     // Web Application Firewall enabled
            Authentication     string   // "mfa", "2fa", "basic", "none"
            Encryption         bool     // Data encrypted in transit/at rest
            RateLimiting       bool     // Rate limiting enabled
            InputValidation    bool     // Input validation in place
            CustomControls     []string // Additional controls
        }
    }
}
```

---

## Example config.yaml

### Minimal

```yaml
project:
  name: "my-api"
  description: "Customer-facing REST API"

context:
  exposure: "internet"
  data_sensitivity: "high"
  business_criticality: "critical"
```

### Complete

```yaml
project:
  name: "payment-service"
  description: "PCI-DSS compliant payment processing service"

context:
  exposure: "internet"
  data_sensitivity: "critical"
  business_criticality: "critical"
  
  compliance_requirements:
    - PCI-DSS
    - SOC2
    - GDPR
  
  notes: |
    - Handles customer credit card data
    - Processes refunds and chargebacks
    - Integrates with Stripe and PayPal
    - Critical for business operations
  
  controls:
    waf: true
    authentication: "mfa"
    encryption: true
    rate_limiting: true
    input_validation: true
    custom_controls:
      - "Hardware security module for key storage"
      - "Daily security scanning with Trivy"
      - "Incident response team on standby"
```

---

## Field Definitions

### Project Metadata

#### `project.name`
- **Type:** string
- **Required:** yes
- **Purpose:** Identifies the application
- **Example:** "payment-service", "api-gateway", "website"

#### `project.description`
- **Type:** string
- **Required:** yes
- **Purpose:** Brief description for context
- **Example:** "PCI-DSS compliant payment processing service"

### Context Factors

#### `context.exposure`
- **Type:** enum
- **Values:** `"internal"`, `"private"`, `"internet"`
- **Required:** yes
- **Meaning:**
  - `"internal"` — Only accessible to employees on corporate network
  - `"private"` — Accessible via VPN or private cloud only
  - `"internet"` — Public-facing, accessible from anywhere
- **Impact on scoring:** Internet-facing increases threat agent likelihood

#### `context.data_sensitivity`
- **Type:** enum
- **Values:** `"low"`, `"medium"`, `"high"`, `"critical"`
- **Required:** yes
- **Meaning:**
  - `"low"` — Public data only
  - `"medium"` — Internal data, non-financial
  - `"high"` — Customer PII, payment data (non-card)
  - `"critical"` — Credit card data, health records, secrets
- **Impact on scoring:** Higher sensitivity increases business impact

#### `context.business_criticality`
- **Type:** enum
- **Values:** `"low"`, `"medium"`, `"high"`, `"critical"`
- **Required:** yes
- **Meaning:**
  - `"low"` — Nice-to-have, can be down for days
  - `"medium"` — Important, should be available most of the time
  - `"high"` — Critical, must be available 99%+ of the time
  - `"critical"` — Business-critical, revenue-impacting downtime
- **Impact on scoring:** Higher criticality increases impact

#### `context.compliance_requirements`
- **Type:** array of strings
- **Required:** no
- **Examples:** `["GDPR", "PCI-DSS", "HIPAA", "SOC2", "FedRAMP"]`
- **Purpose:** Regulatory/standards context
- **Impact on scoring:** Violations increase business impact (especially NC/PV factors)

#### `context.notes`
- **Type:** string
- **Required:** no
- **Purpose:** Free-form context for LLM
- **Example:**
  ```
  - Handles customer PII under GDPR
  - Critical for business revenue
  - Integrates with external APIs
  - Team on-call 24/7
  ```
- **Impact on scoring:** Provided to LLM as additional context

### Controls

#### `controls.waf`
- **Type:** boolean
- **Default:** false
- **Meaning:** Web Application Firewall protecting the application
- **Impact:** Reduces vulnerability factor score

#### `controls.authentication`
- **Type:** string
- **Values:** `"none"`, `"basic"`, `"2fa"`, `"mfa"`, `"custom"`
- **Default:** `"none"`
- **Meaning:** Authentication strength
- **Impact:** Stronger auth reduces threat agent likelihood

#### `controls.encryption`
- **Type:** boolean
- **Default:** false
- **Meaning:** Data encrypted in transit and at rest
- **Impact:** Reduces technical impact (confidentiality)

#### `controls.rate_limiting`
- **Type:** boolean
- **Default:** false
- **Meaning:** Rate limiting enabled to prevent abuse
- **Impact:** Reduces vulnerability exploitation likelihood

#### `controls.input_validation`
- **Type:** boolean
- **Default:** false
- **Meaning:** Strict input validation on all user-facing endpoints
- **Impact:** Reduces vulnerability factor (ease of exploit)

#### `controls.custom_controls`
- **Type:** array of strings
- **Default:** `[]`
- **Purpose:** Additional security controls
- **Examples:**
  - "Hardware security module for key storage"
  - "Daily automated security scans"
  - "Bug bounty program active"
  - "SOC team monitoring 24/7"
- **Impact:** Provided to LLM as context

---

## Loading & Validation

### `LoadConfig()`

```go
func LoadConfig(configPath string) (*Config, error)
```

**Steps:**
1. Read YAML file
2. Unmarshal into Config struct
3. Validate required fields
4. Validate enum values
5. Set defaults
6. Return or error

**Example:**
```go
config, err := riskconfig.LoadConfig("config.yaml")
if err != nil {
    return fmt.Errorf("failed to load config: %w", err)
}
```

### Validation Rules

```go
func (c *Config) Validate() error {
    // Required fields
    if c.Project.Name == "" {
        return errors.New("project.name is required")
    }
    
    if c.Project.Description == "" {
        return errors.New("project.description is required")
    }
    
    // Enum validation
    exposure := c.Context.Exposure
    if exposure != "internal" && exposure != "private" && exposure != "internet" {
        return fmt.Errorf("context.exposure must be 'internal', 'private', or 'internet', got: %s", exposure)
    }
    
    dataSensitivity := c.Context.DataSensitivity
    if !isValidDataSensitivity(dataSensitivity) {
        return fmt.Errorf("context.data_sensitivity must be one of: low, medium, high, critical")
    }
    
    // ... more validations
    
    return nil
}
```

### Error Messages

**Example errors:**
```
Failed to load config.yaml:
  - project.name is required
  - context.exposure must be 'internal', 'private', or 'internet', got: 'dmz'
  - context.data_sensitivity must be one of: low, medium, high, critical, got: 'extremely-high'
```

---

## Using Config in Generator

### System Prompt Construction

Config is embedded in the LLM system prompt:

```
You are a vulnerability risk assessment expert using the OWASP Risk Rating methodology.
Assess each CVE in the context of:

PROJECT: payment-service
- Description: PCI-DSS compliant payment processing service

EXPOSURE: Internet-facing (publicly accessible)
DATA SENSITIVITY: Critical (handles credit card data)
BUSINESS CRITICALITY: Critical (revenue-impacting)

COMPLIANCE: PCI-DSS, SOC2, GDPR
COMPLIANCE IMPACT: Violations have severe business impact

CONTROLS IN PLACE:
- WAF: enabled
- Authentication: MFA required
- Encryption: TLS 1.3 in transit, AES-256 at rest
- Rate limiting: enabled
- Input validation: strict

ADDITIONAL CONTEXT:
- Handles customer credit card data
- Processes refunds and chargebacks
- Integrates with Stripe and PayPal
- Critical for business operations

With this context, calculate OWASP Risk Rating scores for each CVE...
```

### Scoring Impact

**Example: RCE in a rarely-used library**

```
Generic (CVSS): 8.8 HIGH

With vens config showing:
- Exposure: internet (increases threat likelihood)
- Data sensitivity: critical (increases business impact)
- Business criticality: critical (increases business impact)
- Controls: WAF, rate limiting (reduce vulnerability/threat)

Result: Context-aware score might be:
- If vulnerable code path not reachable: 15.0 MEDIUM
- If vulnerable code path is reachable: 52.0 HIGH

(Actual scores depend on LLM assessment)
```

---

## File Location & Discovery

### Default Location
```bash
# In same directory where vens is run
./config.yaml
```

### Explicit Path
```bash
vens generate --config-file /path/to/custom/config.yaml ...
```

### Discovery Algorithm
```go
func findConfigFile(explicit string) (string, error) {
    if explicit != "" {
        return explicit, verifyExists(explicit)
    }
    
    // Try default locations in order
    defaults := []string{
        "config.yaml",
        "config.yml",
        ".vens/config.yaml",
    }
    
    for _, path := range defaults {
        if fileExists(path) {
            return path, nil
        }
    }
    
    return "", fmt.Errorf("config file not found and --config-file not specified")
}
```

---

## Examples

### Example 1: Startup MVP

```yaml
project:
  name: "startup-api"
  description: "Early-stage SaaS API"

context:
  exposure: "internet"
  data_sensitivity: "medium"
  business_criticality: "high"
  notes: |
    - Small team, minimal security budget
    - Using managed hosting (Heroku, Fly.io)
    - No PII stored, user data only
```

### Example 2: Financial Services

```yaml
project:
  name: "banking-api"
  description: "Core banking platform"

context:
  exposure: "internet"
  data_sensitivity: "critical"
  business_criticality: "critical"
  
  compliance_requirements:
    - PCI-DSS
    - HIPAA
    - SOC2
    - Gramm-Leach-Bliley
  
  controls:
    waf: true
    authentication: "mfa"
    encryption: true
    rate_limiting: true
    input_validation: true
    custom_controls:
      - "HSM for key storage"
      - "Intrusion detection system"
      - "Dedicated security team"
      - "Bug bounty program"
```

### Example 3: Internal Tool

```yaml
project:
  name: "internal-dashboard"
  description: "Internal analytics dashboard for employees"

context:
  exposure: "private"
  data_sensitivity: "medium"
  business_criticality: "low"
  notes: |
    - Only accessible via VPN
    - Metrics and reporting only
    - No customer data
    - Can be down during maintenance windows
  
  controls:
    authentication: "2fa"
    encryption: true
```

---

## YAML Schema (Reference)

```yaml
project:
  name: string (required)
  description: string (required)

context:
  exposure: "internal" | "private" | "internet" (required)
  data_sensitivity: "low" | "medium" | "high" | "critical" (required)
  business_criticality: "low" | "medium" | "high" | "critical" (required)
  compliance_requirements: [string] (optional)
  notes: string (optional)
  controls:
    waf: boolean (optional, default: false)
    authentication: "none" | "basic" | "2fa" | "mfa" | "custom" (optional)
    encryption: boolean (optional, default: false)
    rate_limiting: boolean (optional, default: false)
    input_validation: boolean (optional, default: false)
    custom_controls: [string] (optional)
```

---

## Testing

### Unit Tests: `riskconfig_test.go`

```go
func TestLoadConfig(t *testing.T) {
    yaml := `
project:
  name: "test-app"
  description: "Test application"
context:
  exposure: "internet"
  data_sensitivity: "high"
  business_criticality: "critical"
`
    tmpfile, _ := ioutil.TempFile("", "config-*.yaml")
    tmpfile.WriteString(yaml)
    
    config, err := LoadConfig(tmpfile.Name())
    
    assert.NoError(t, err)
    assert.Equal(t, "test-app", config.Project.Name)
    assert.Equal(t, "internet", config.Context.Exposure)
}

func TestValidateConfig(t *testing.T) {
    // Test invalid exposure value
    config := &Config{
        Project: struct {
            Name        string
            Description string
        }{Name: "test", Description: "test"},
        Context: struct {
            Exposure string
            // ...
        }{Exposure: "invalid"},
    }
    
    err := config.Validate()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "exposure")
}
```

### Integration Tests

```bash
# Test vens generate with various config scenarios
vens generate --config-file testdata/config-minimal.yaml report.json output1.json
vens generate --config-file testdata/config-full.yaml report.json output2.json
```

---

## Best Practices

### 1. Start Simple
Begin with minimal config (required fields only) and iterate as you learn vens.

### 2. Document Your Context
Use `notes` field to explain why you chose specific values. Helps LLM understand nuances.

### 3. Review Scores
After first run, review generated OWASP scores. Do they match your expectations? Adjust config if needed.

### 4. Iterate on Controls
As you implement security controls, update config.yaml to reflect them. This will improve scoring accuracy.

### 5. Version Control
Commit config.yaml to git. It's part of your security posture documentation.

---

## See Also

- **[Generator Codemap](./generator.md)** — Uses config for LLM context
- **[CLI Codemap](./cli.md)** — `--config-file` flag
- **docs/guides/configuration.md** — User guide for writing config.yaml
- **CONTRIBUTING.md** — Testing config-related changes

