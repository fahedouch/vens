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

// Package generator provides LLM-based OWASP risk scoring for vulnerabilities.
// The approach is inspired by github.com/AkihiroSuda/vexllm for LLM prompt structure.
package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/tmc/langchaingo/jsonschema"
	"github.com/tmc/langchaingo/llms"
	"github.com/venslabs/vens/pkg/llm"
	outputhandler "github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

const (
	DefaultBatchSize        = 10
	DefaultSleepOnRateLimit = 10 * time.Second
	DefaultRetryOnRateLimit = 10
)

// Vulnerability represents a single vulnerability from a scanner report.
type Vulnerability struct {
	VulnID      string `json:"vulnId"`
	PkgID       string `json:"pkgId"`
	PkgName     string `json:"pkgName"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// llmOutputEntry represents the LLM response for a single vulnerability.
// The LLM rates each of the 4 OWASP factors (0-9 scale), and the final score
// is calculated in Go code for mathematical accuracy.
type llmOutputEntry struct {
	VulnID             string  `json:"vulnId"`
	ThreatAgentScore   float64 `json:"threat_agent_score"`  // 0-9: Threat actor factors (skill, motive, opportunity, size)
	VulnerabilityScore float64 `json:"vulnerability_score"` // 0-9: Vulnerability factors (ease of discovery, ease of exploit)
	TechnicalImpact    float64 `json:"technical_impact"`    // 0-9: Technical impact (loss of CIA)
	BusinessImpact     float64 `json:"business_impact"`     // 0-9: Business impact (financial, reputation, compliance)
	Reasoning          string  `json:"reasoning"`           // Brief explanation of the scoring
}

// llmOutput wraps the array of results from LLM.
type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// Opts configures the Generator.
type Opts struct {
	LLM         llms.Model
	Temperature float64
	BatchSize   int // Avoid high values to avoid rate limit
	Seed        int

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int
	DebugDir         string

	// Config carries user-provided context hints loaded from config.yaml.
	Config *riskconfig.Config
}

// Generator produces OWASP risk scores using LLM analysis.
type Generator struct {
	o Opts
}

// New creates a new Generator with the given options.
func New(o Opts) (*Generator, error) {
	g := &Generator{
		o: o,
	}

	if g.o.LLM == nil {
		return nil, errors.New("no model")
	}
	if g.o.BatchSize == 0 {
		g.o.BatchSize = DefaultBatchSize
	}
	if g.o.SleepOnRateLimit == 0 {
		g.o.SleepOnRateLimit = DefaultSleepOnRateLimit
	}
	if g.o.RetryOnRateLimit == 0 {
		g.o.RetryOnRateLimit = DefaultRetryOnRateLimit
	}
	if g.o.DebugDir != "" {
		if err := os.MkdirAll(g.o.DebugDir, 0755); err != nil {
			slog.Error("failed to create the debug dir", "error", err)
			g.o.DebugDir = ""
		}
	}
	return g, nil
}

// GenerateRiskScore generates contextual OWASP risk scores for the given vulnerabilities.
// It uses the LLM to calculate the OWASP risk score for each vulnerability based on
// the project context hints provided in config.yaml.
func (g *Generator) GenerateRiskScore(ctx context.Context, vulns []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	batchSize := g.o.BatchSize
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		if err := g.generateRiskScore(ctx, batch, h); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) generateRiskScore(ctx context.Context, vulnBatch []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	if g.o.Config == nil {
		return errors.New("config not initialized; load config.yaml first")
	}

	// Call LLM to calculate OWASP scores for each vulnerability
	scores, err := g.evaluateOWASPScores(ctx, vulnBatch)
	if err != nil {
		return fmt.Errorf("LLM evaluation failed: %w", err)
	}

	// Build VulnRating group using Go-calculated scores
	group := make([]outputhandler.VulnRating, 0, len(vulnBatch))
	for _, entry := range scores {
		if entry.VulnID == "" {
			continue
		}

		// Calculate final OWASP score using the formula:
		// Risk = Likelihood × Impact = ((ThreatAgent + Vulnerability)/2) × ((TechImpact + BusinessImpact)/2)
		likelihoodScore := (entry.ThreatAgentScore + entry.VulnerabilityScore) / 2.0
		impactScore := (entry.TechnicalImpact + entry.BusinessImpact) / 2.0
		owaspScore := likelihoodScore * impactScore // Range: 0-81

		score := clampScore(owaspScore)
		severity := riskconfig.RiskSeverity(score)

		slog.InfoContext(ctx, "vuln_risk_score",
			"vuln", entry.VulnID,
			"threat_agent", entry.ThreatAgentScore,
			"vulnerability", entry.VulnerabilityScore,
			"technical_impact", entry.TechnicalImpact,
			"business_impact", entry.BusinessImpact,
			"likelihood", fmt.Sprintf("%.2f", likelihoodScore),
			"impact", fmt.Sprintf("%.2f", impactScore),
			"score", fmt.Sprintf("%.2f", score),
			"severity", severity,
		)

		group = append(group, outputhandler.VulnRating{
			VulnID: entry.VulnID,
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.Severity(severity),
			},
		})
	}

	if len(group) == 0 {
		return nil
	}
	if h != nil {
		return h(group)
	}
	return nil
}

// evaluateOWASPScores calls the LLM to calculate the OWASP risk score for each vulnerability.
// The LLM uses the project context hints to determine the appropriate score.
//
// TODO: Optimization opportunity - Only ThreatAgent, TechnicalImpact, and BusinessImpact can be calculated
// deterministically from config. Consider moving them to Go code and using LLM only for VulnerabilityScore
// (which requires analyzing CVE descriptions). This would reduce costs by ~66% and improve consistency.
func (g *Generator) evaluateOWASPScores(ctx context.Context, vulns []Vulnerability) ([]llmOutputEntry, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured")
	}

	var buf bytes.Buffer
	callOpts := []llms.CallOption{
		llms.WithJSONMode(),
		llms.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
			buf.Write(chunk)
			return nil
		}),
	}

	if g.o.Temperature > 0.0 {
		slog.Debug("Using temperature", "temperature", g.o.Temperature)
		callOpts = append(callOpts, llms.WithTemperature(g.o.Temperature))
	}
	if g.o.Seed != 0 {
		slog.Debug("Using seed", "seed", g.o.Seed)
		callOpts = append(callOpts, llms.WithSeed(g.o.Seed))
	}

	// Build system prompt with context hints
	systemPrompt := g.buildSystemPrompt()

	// Build JSON schema for structured output
	schema := g.buildOutputSchema()
	schemaJ, err := schema.MarshalJSON()
	if err != nil {
		return nil, err
	}

	systemPrompt += "#### Output format: JSON Schema\n"
	systemPrompt += string(schemaJ) + "\n"
	systemPrompt += "#### Output Example\n"
	systemPrompt += "```json\n" + g.buildOutputExample() + "\n```\n"

	// Only ollama and openai supports WithJSONSchema
	// Reference: https://github.com/tmc/langchaingo/pull/1302
	callOpts = append(callOpts, llms.WithJSONSchema(schema))

	// Build human prompt with vulnerabilities
	vulnsJSON, err := json.Marshal(vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vulnerabilities: %w", err)
	}
	humanPrompt := string(vulnsJSON)

	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, humanPrompt),
	}

	// Debug: save prompts if debug directory is configured
	if g.o.DebugDir != "" {
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "system.prompt"), []byte(systemPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write system.prompt", "error", err)
		}
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "human.prompt"), []byte(humanPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write human.prompt", "error", err)
		}
	}

	// Call LLM with retry on rate limit
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		buf.Reset()
		_, err := g.o.LLM.GenerateContent(c, msgs, callOpts...)
		return err
	}); err != nil {
		return nil, err
	}

	// Parse LLM response
	var resp llmOutput
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("unable to parse LLM output: %w: %q", err, buf.String())
	}

	// Calculate final OWASP scores in Go for mathematical accuracy
	for i := range resp.Results {
		entry := &resp.Results[i]

		// Validate and clamp component scores to 0-9 range
		entry.ThreatAgentScore = clampScore09(entry.ThreatAgentScore)
		entry.VulnerabilityScore = clampScore09(entry.VulnerabilityScore)
		entry.TechnicalImpact = clampScore09(entry.TechnicalImpact)
		entry.BusinessImpact = clampScore09(entry.BusinessImpact)

		// Log component scores for debugging
		slog.DebugContext(ctx, "owasp_components",
			"vuln", entry.VulnID,
			"threat_agent", entry.ThreatAgentScore,
			"vulnerability", entry.VulnerabilityScore,
			"technical_impact", entry.TechnicalImpact,
			"business_impact", entry.BusinessImpact,
			"reasoning", entry.Reasoning,
		)
	}

	return resp.Results, nil
}

// buildSystemPrompt creates the system prompt for OWASP score calculation.
// Inspired by github.com/AkihiroSuda/vexllm prompt structure.
func (g *Generator) buildSystemPrompt() string {
	prompt := `You are a security analyst evaluating vulnerabilities in the following system:

`
	if g.o.Config != nil {
		prompt += g.o.Config.FormatForLLM()
	}

	prompt += `
For EACH vulnerability, analyze its description/title and rate 4 OWASP factors (0-9):

1. THREAT_AGENT: Who can exploit this?
   - Read vulnerability type and consider system exposure
   - Base: exposure (internal:2-3, private:4-6, internet:7-9)
   - Adjust: +1 if critical business attracts skilled attackers

2. VULNERABILITY: How easy to exploit THIS specific vulnerability?
   IMPORTANT: Analyze the actual vulnerability, not just severity label
   - Read description: Is it a known issue? Exploit available? Common weakness?
   - Discovery: 1-3=obscure/needs source, 4-6=scanner finds it, 7-9=trivial/public advisory
   - Exploitability: 1-3=complex/theoretical, 4-6=requires skill, 7-9=PoC exists/tool automates it
   - Formula: avg(discovery, exploit) + severity_bonus (CRITICAL:+2, HIGH:+1, MEDIUM:0, LOW:-1)`

	// Add controls adjustment only if any controls are present
	if g.o.Config != nil {
		controls := g.o.Config.Context.Controls
		hasControls := controls.WAF || controls.IDS || controls.EDR || controls.Segmentation || controls.ZeroTrust
		if hasControls {
			prompt += `
   - Controls reduce score: WAF/IDS/EDR:-2, Segmentation/ZeroTrust:-1`
		}
	}

	prompt += `
   - Clamp result to 1-9

3. TECHNICAL_IMPACT: What can attacker access if exploited?
   - Identify vulnerability type from title/description:
     * Data breach (SQLi, Path Traversal, XXE): affects Confidentiality + Integrity
     * Code execution (RCE, Deserialization): affects all CIA
     * Denial of Service (DoS, Resource Exhaustion): affects Availability
     * Auth bypass (IDOR, broken access): affects Confidentiality + Accountability
   - Score using system sensitivity:`

	// Show mapping based on what's available
	prompt += `
     * Confidentiality/Integrity: data_sensitivity (low:1-3, medium:4-6, high:7-8, critical:9)`

	if g.o.Config != nil && g.o.Config.Context.AvailabilityRequirement != nil {
		prompt += `
     * Availability: availability_requirement (low:1-3, medium:4-6, high:7-8, critical:9)`
	} else {
		prompt += `
     * Availability: use business_criticality (low:1-3, medium:4-6, high:7-8, critical:9)`
	}

	if g.o.Config != nil && g.o.Config.Context.AuditRequirement != nil {
		prompt += `
     * Accountability: audit_requirement (low:1-3, medium:4-6, high:7-9)`
	}

	prompt += `
   - Return the HIGHEST applicable impact score

4. BUSINESS_IMPACT: Business consequences if exploited?
   - Base: business_criticality (low:1-3, medium:4-6, high:7-8, critical:9)`

	if g.o.Config != nil && len(g.o.Config.Context.ComplianceRequirements) > 0 {
		prompt += `
   - Add +2 if vulnerability affects compliance (data breach, audit failure, etc.)`
	}

	prompt += `
   - Cap at 9

CRITICAL: Score based on the SPECIFIC vulnerability characteristics, not just its severity label.
Output: 4 integer scores (0-9) + concise reasoning explaining your analysis of THIS vulnerability.
`
	return prompt
}

// buildOutputSchema creates the JSON schema for the LLM output.
// The LLM must rate each of the 4 OWASP factors separately (0-9 scale).
// The final score calculation is done in Go code for accuracy.
func (g *Generator) buildOutputSchema() *jsonschema.Definition {
	return &jsonschema.Definition{
		Type: jsonschema.Object,
		Properties: map[string]jsonschema.Definition{
			"results": {
				Type: jsonschema.Array,
				Items: &jsonschema.Definition{
					Type: jsonschema.Object,
					Properties: map[string]jsonschema.Definition{
						"vulnId": {
							Type:        jsonschema.String,
							Description: "The vulnerability ID from the input (e.g., CVE-2024-1234)",
						},
						"threat_agent_score": {
							Type:        jsonschema.Number,
							Description: "Threat Agent score (0-9): skill level, motive, opportunity, size",
						},
						"vulnerability_score": {
							Type:        jsonschema.Number,
							Description: "Vulnerability score (0-9): ease of discovery, ease of exploit",
						},
						"technical_impact": {
							Type:        jsonschema.Number,
							Description: "Technical Impact score (0-9): loss of confidentiality, integrity, availability, accountability",
						},
						"business_impact": {
							Type:        jsonschema.Number,
							Description: "Business Impact score (0-9): financial damage, reputation damage, non-compliance, privacy violation",
						},
						"reasoning": {
							Type:        jsonschema.String,
							Description: "Brief explanation of each score (2-3 sentences)",
						},
					},
					Required: []string{
						"vulnId",
						"threat_agent_score",
						"vulnerability_score",
						"technical_impact",
						"business_impact",
						"reasoning",
					},
				},
			},
		},
		Required: []string{"results"},
	}
}

// buildOutputExample returns an example output for the LLM.
func (g *Generator) buildOutputExample() string {
	return `{
  "results": [
    {
      "vulnId": "CVE-2024-1234",
      "threat_agent_score": 8,
      "vulnerability_score": 7,
      "technical_impact": 8,
      "business_impact": 9,
      "reasoning": "RCE in OpenSSL: ThreatAgent=8 (internet-exposed, attracts skilled attackers), Vulnerability=7 (known exploit exists), TechImpact=8 (full system compromise), BusinessImpact=9 (critical system + compliance risk)"
    },
    {
      "vulnId": "CVE-2024-5678",
      "threat_agent_score": 3,
      "vulnerability_score": 4,
      "technical_impact": 4,
      "business_impact": 5,
      "reasoning": "DoS in logging lib: ThreatAgent=3 (internal only), Vulnerability=4 (requires config), TechImpact=4 (availability impact medium), BusinessImpact=5 (medium criticality system)"
    }
  ]
}`
}

// clampScore ensures the score is within [0, 81].
func clampScore(v float64) float64 {
	if v < 0.0 {
		return 0.0
	}
	if v > 81.0 {
		return 81.0
	}
	return v
}

// clampScore09 ensures a component score is within [0, 9].
func clampScore09(v float64) float64 {
	if v < 0.0 {
		return 0.0
	}
	if v > 9.0 {
		return 9.0
	}
	return v
}
