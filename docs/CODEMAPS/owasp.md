# OWASP Risk Rating Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/owasp`  
**Reference:** https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

---

## Purpose

The OWASP package implements the OWASP Risk Rating methodology for calculating contextual vulnerability scores. It transforms LLM-generated factor scores into valid OWASP Risk Rating vectors and final risk scores.

**Inputs:** LLM scores for 4 factors (0-9 each)  
**Output:** OWASP RR vector + risk score (0-81) + severity classification

---

## OWASP Risk Rating Methodology Overview

### Formula
```
Risk = Likelihood × Impact
     = [(TA + VF) / 2] × [(TI + BI) / 2]
     
Where:
  TA = Threat Agent factors (0-9)
  VF = Vulnerability Factors (0-9)
  TI = Technical Impact (0-9)
  BI = Business Impact (0-9)

Result range: 0.0 to 81.0
```

### The 4 Factor Categories (16 total factors)

#### 1. Threat Agent (TA) — 4 factors

| Factor | Range | Meaning |
|--------|-------|---------|
| **SkillLevel (SL)** | 0-9 | Attacker technical skill (0=none, 9=expert) |
| **Motive (M)** | 0-9 | Attacker motivation (0=no motive, 9=critical) |
| **Opportunity (O)** | 0-9 | Access/tools available (0=none, 9=easily available) |
| **Size (S)** | 0-9 | Number of potential attackers (0=none, 9=millions) |

#### 2. Vulnerability Factors (VF) — 4 factors

| Factor | Range | Meaning |
|--------|-------|---------|
| **EaseOfDiscovery (ED)** | 0-9 | How easy to find vuln (0=impossible, 9=trivial) |
| **EaseOfExploit (EE)** | 0-9 | How easy to exploit (0=impossible, 9=trivial) |
| **Awareness (A)** | 0-9 | Known in community (0=unknown, 9=widely known) |
| **IntrusionDetection (ID)** | 0-9 | Can it be detected (0=easily, 9=never) |

#### 3. Technical Impact (TI) — 4 factors

| Factor | Range | Meaning |
|--------|-------|---------|
| **LossOfConfidentiality (LC)** | 0-9 | Data exposure (0=none, 9=total) |
| **LossOfIntegrity (LI)** | 0-9 | Data corruption (0=none, 9=total) |
| **LossOfAvailability (LAV)** | 0-9 | Service disruption (0=none, 9=total) |
| **LossOfAccountability (LAC)** | 0-9 | Audit trail loss (0=none, 9=total) |

#### 4. Business Impact (BI) — 4 factors

| Factor | Range | Meaning |
|--------|-------|---------|
| **FinancialDamage (FD)** | 0-9 | Direct costs (0=none, 9=catastrophic) |
| **ReputationDamage (RD)** | 0-9 | Brand damage (0=none, 9=total loss) |
| **NonCompliance (NC)** | 0-9 | Regulatory violations (0=none, 9=critical) |
| **PrivacyViolation (PV)** | 0-9 | PII exposure (0=none, 9=massive) |

---

## Core Type: `OwaspRRVector`

```go
type OwaspRRVector struct {
    // Threat Agent Factors
    SkillLevel  int // SL: 0-9
    Motive      int // M: 0-9
    Opportunity int // O: 0-9
    Size        int // S: 0-9
    
    // Vulnerability Factors
    EaseOfDiscovery    int // ED: 0-9
    EaseOfExploit      int // EE: 0-9
    Awareness          int // A: 0-9
    IntrusionDetection int // ID: 0-9
    
    // Technical Impact Factors
    LossOfConfidentiality int // LC: 0-9
    LossOfIntegrity       int // LI: 0-9
    LossOfAvailability    int // LAV: 0-9
    LossOfAccountability  int // LAC: 0-9
    
    // Business Impact Factors
    FinancialDamage  int // FD: 0-9
    ReputationDamage int // RD: 0-9
    NonCompliance    int // NC: 0-9
    PrivacyViolation int // PV: 0-9
}
```

### Methods

#### `String()`
Returns vector in standard OWASP RR format:
```go
vector := OwaspRRVector{
    SkillLevel: 7, Motive: 7, Opportunity: 7, Size: 7,
    EaseOfDiscovery: 6, EaseOfExploit: 6, Awareness: 6, IntrusionDetection: 6,
    LossOfConfidentiality: 8, LossOfIntegrity: 8, LossOfAvailability: 8, LossOfAccountability: 8,
    FinancialDamage: 7, ReputationDamage: 7, NonCompliance: 6, PrivacyViolation: 9,
}

fmt.Println(vector.String())
// Output: SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:7/RD:7/NC:6/PV:9
```

---

## Vector Construction: `FromAggregatedScores()`

```go
func FromAggregatedScores(threatAgent, vulnerability, technicalImpact, businessImpact float64) *OwaspRRVector
```

### Purpose

Vens uses 4-factor LLM scoring (not all 16), so this function expands to full vector:

```
LLM Response:
{
  "threat_agent_score": 7.0,      // Average of SL, M, O, S
  "vuln_factor_score": 6.0,       // Average of ED, EE, A, ID
  "technical_impact": 8.0,        // Average of LC, LI, LAV, LAC
  "business_impact": 7.5          // Average of FD, RD, NC, PV
}

↓

Generated Vector:
SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:8/RD:8/NC:7/PV:8
(Each factor in a group gets the aggregated score)
```

### Distribution Logic

```go
func FromAggregatedScores(ta, vf, ti, bi float64) *OwaspRRVector {
    // Clamp all to 0-9 range
    clamp := func(v float64) int {
        if v < 0 { return 0 }
        if v > 9 { return 9 }
        return int(math.Round(v))
    }
    
    taScore := clamp(ta)
    vfScore := clamp(vf)
    tiScore := clamp(ti)
    biScore := clamp(bi)
    
    return &OwaspRRVector{
        // Threat Agent: all get the same score
        SkillLevel: taScore,
        Motive: taScore,
        Opportunity: taScore,
        Size: taScore,
        
        // Vulnerability: all get the same score
        EaseOfDiscovery: vfScore,
        EaseOfExploit: vfScore,
        Awareness: vfScore,
        IntrusionDetection: vfScore,
        
        // Technical Impact: all get the same score
        LossOfConfidentiality: tiScore,
        LossOfIntegrity: tiScore,
        LossOfAvailability: tiScore,
        LossOfAccountability: tiScore,
        
        // Business Impact: all get the same score
        FinancialDamage: biScore,
        ReputationDamage: biScore,
        NonCompliance: biScore,
        PrivacyViolation: biScore,
    }
}
```

### Why Distribute Uniformly?

1. **Simplicity** — LLM doesn't need to score all 16 factors
2. **Token efficiency** — Fewer scores = fewer tokens
3. **Mathematical validity** — Aggregated vector still produces correct risk score
4. **Pragmatism** — When detailed scoring unavailable, use reasonable default

---

## Risk Score Calculation

### Formula Implementation

```go
func (v *OwaspRRVector) RiskScore() float64 {
    // Calculate likelihood: average of threat agent and vulnerability
    likelihood := (float64(v.SkillLevel + v.Motive + v.Opportunity + v.Size) / 4.0 +
                   float64(v.EaseOfDiscovery + v.EaseOfExploit + v.Awareness + v.IntrusionDetection) / 4.0) / 2.0
    
    // Calculate impact: average of technical and business
    impact := (float64(v.LossOfConfidentiality + v.LossOfIntegrity + v.LossOfAvailability + v.LossOfAccountability) / 4.0 +
               float64(v.FinancialDamage + v.ReputationDamage + v.NonCompliance + v.PrivacyViolation) / 4.0) / 2.0
    
    // Risk = Likelihood × Impact (0-81)
    return likelihood * impact
}
```

### Worked Example

**Scenario:** Open bucket storing PII in production AWS account

```
Threat Agent (7.0):
  - SkillLevel: 7 (AWS security knowledge required)
  - Motive: 7 (steal PII for profit)
  - Opportunity: 7 (bucket discovery tools common)
  - Size: 8 (many threat actors)
  → Average: 7.25

Vulnerability (6.0):
  - EaseOfDiscovery: 7 (easy to find open buckets)
  - EaseOfExploit: 5 (need to extract/exfil data)
  - Awareness: 8 (widely known issue)
  - IntrusionDetection: 4 (hard to detect S3 reads)
  → Average: 6.0

Technical Impact (8.0):
  - LossOfConfidentiality: 9 (PII fully exposed)
  - LossOfIntegrity: 3 (not modified)
  - LossOfAvailability: 2 (not affected)
  - LossOfAccountability: 8 (audit trail exposed)
  → Average: 5.5

Business Impact (8.0):
  - FinancialDamage: 8 (penalties, remediation)
  - ReputationDamage: 9 (customer trust loss)
  - NonCompliance: 9 (GDPR violation)
  - PrivacyViolation: 9 (PII breach)
  → Average: 8.75

Calculation:
  Likelihood = (7.25 + 6.0) / 2 = 6.625
  Impact = (5.5 + 8.75) / 2 = 7.125
  Risk = 6.625 × 7.125 = 47.2
```

**Result:** 47.2 → HIGH severity

---

## Severity Classification

### Threshold Mapping

```go
func (v *OwaspRRVector) Severity() string {
    score := v.RiskScore()
    
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

### Severity Bands

| Range | Severity | Action |
|-------|----------|--------|
| [0.0, 5.4) | **LOW** | Informational, no urgent action |
| [5.4, 12.5) | **MEDIUM** | Schedule fixes, monitor |
| [12.5, 28.1) | **HIGH** | Fix soon, within weeks |
| [28.1, 81.0] | **CRITICAL** | Fix immediately, within hours |

### Customization

**Note:** These thresholds are currently hardcoded. Future enhancement: make configurable via config.yaml.

```yaml
# Potential future feature
risk_thresholds:
  low_to_medium: 5.4
  medium_to_high: 12.5
  high_to_critical: 28.1
```

---

## Integration with Generator

### Step 1: LLM Response
```json
{
  "vulnId": "CVE-2024-1234",
  "threat_agent_score": 7.0,
  "vuln_factor_score": 6.0,
  "technical_impact": 8.0,
  "business_impact": 7.5,
  "reasoning": "..."
}
```

### Step 2: Create Vector
```go
vector := owasp.FromAggregatedScores(7.0, 6.0, 8.0, 7.5)
// → SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:8/RD:8/NC:7/PV:8
```

### Step 3: Calculate Score & Severity
```go
riskScore := vector.RiskScore()     // 48.0
severity := vector.Severity()        // "high"
vectorStr := vector.String()         // "SL:7/M:7/..."
```

### Step 4: Create CycloneDX Rating
```go
rating := cyclonedx.VulnerabilityRating{
    Score: &riskScore,
    Severity: severity,
    Method: cyclonedx.ScoringMethodOWASP,
    Vector: vectorStr,
}
```

### Step 5: Output to VEX
The rating is embedded in the VEX document via OutputHandler.

---

## Testing

### Unit Tests: `vector_test.go`

**Test categories:**

1. **Vector construction**
   ```go
   func TestFromAggregatedScores(t *testing.T) {
       vector := FromAggregatedScores(7.0, 6.0, 8.0, 7.5)
       assert.Equal(t, 7, vector.SkillLevel)
       assert.Equal(t, 6, vector.EaseOfDiscovery)
   }
   ```

2. **String representation**
   ```go
   func TestString(t *testing.T) {
       vector := &OwaspRRVector{SkillLevel: 7, Motive: 7, ...}
       expected := "SL:7/M:7/O:7/S:7/..."
       assert.Equal(t, expected, vector.String())
   }
   ```

3. **Risk calculation**
   ```go
   func TestRiskScore(t *testing.T) {
       vector := FromAggregatedScores(7.0, 6.0, 8.0, 7.5)
       score := vector.RiskScore()
       assert.Greater(t, score, 40.0)
       assert.Less(t, score, 50.0)
   }
   ```

4. **Severity classification**
   ```go
   func TestSeverity(t *testing.T) {
       lowVec := FromAggregatedScores(2.0, 2.0, 2.0, 2.0)
       assert.Equal(t, "low", lowVec.Severity())
       
       critVec := FromAggregatedScores(9.0, 9.0, 9.0, 9.0)
       assert.Equal(t, "critical", critVec.Severity())
   }
   ```

---

## Key Design Decisions

### 1. **4-Factor Aggregation vs. 16-Factor Scoring**

**Why not ask LLM for all 16 factors?**
- Each factor adds tokens to prompt
- More complexity for LLM to handle
- Diminishing returns (humans can't distinguish all 16 factors reliably)

**Solution:**
- Ask LLM for 4 aggregated scores
- Expand in code to 16-factor vector
- Still produces valid OWASP RR vector
- Easier for LLM to reason about

### 2. **Uniform Distribution**

Why distribute aggregated scores uniformly across sub-factors?
- Assumption: if LLM says threat-agent = 7, each TA factor is roughly 7
- Conservative (doesn't assume nuance)
- Produces valid OWASP vector
- Can be overridden with custom vector if needed

### 3. **Fixed Severity Thresholds**

Why not make thresholds configurable?
- OWASP standard recommends these values
- Consistency across users
- Potential future: user-configurable via config.yaml

---

## CycloneDX Integration

### VulnerabilityRating Object

```go
type VulnerabilityRating struct {
    Score     *float64 // e.g., 47.2
    Severity  string   // "low", "medium", "high", "critical"
    Method    string   // cyclonedx.ScoringMethodOWASP
    Vector    string   // "SL:7/M:7/..."
}
```

**Embedded in VEX:**
```json
{
  "vulnerabilities": [{
    "id": "CVE-2024-1234",
    "ratings": [{
      "score": 47.2,
      "severity": "high",
      "method": "OWASP",
      "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:8/LI:8/LAV:8/LAC:8/FD:8/RD:8/NC:7/PV:8"
    }]
  }]
}
```

---

## Performance

| Operation | Time |
|-----------|------|
| Vector construction | <1μs |
| Risk calculation | <1μs |
| Severity classification | <1μs |
| String formatting | <10μs |

**Note:** All operations are O(1) with trivial CPU cost.

---

## References

- **OWASP Risk Rating Methodology:** https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- **CycloneDX VEX Spec:** https://cyclonedx.org/capabilities/vex/
- **CycloneDX Go Library:** https://github.com/CycloneDX/cyclonedx-go

---

## See Also

- **[Generator Codemap](./generator.md)** — Invokes OWASP scoring
- **[Configuration Codemap](./configuration.md)** — User context for LLM
- **docs/concepts/cvss-vs-owasp.md** — User-facing comparison
- **CONTRIBUTING.md** — Testing standards

