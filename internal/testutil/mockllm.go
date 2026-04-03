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

// Package testutil provides test utilities for vens integration tests.
package testutil

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"

	"github.com/tmc/langchaingo/llms"
)

// MockLLM implements llms.Model for testing purposes.
// It returns deterministic OWASP scores based on vulnerability IDs.
type MockLLM struct{}

// NewMockLLM creates a new mock LLM for testing.
func NewMockLLM() *MockLLM {
	return &MockLLM{}
}

// llmOutputEntry mirrors the structure in generator.go
type llmOutputEntry struct {
	VulnID             string  `json:"vulnId"`
	ThreatAgentScore   float64 `json:"threat_agent_score"`
	VulnerabilityScore float64 `json:"vulnerability_score"`
	TechnicalImpact    float64 `json:"technical_impact"`
	BusinessImpact     float64 `json:"business_impact"`
	Reasoning          string  `json:"reasoning"`
}

type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// GenerateContent implements llms.Model.
// It parses vulnerability IDs from the input and returns deterministic scores.
func (m *MockLLM) GenerateContent(ctx context.Context, messages []llms.MessageContent, options ...llms.CallOption) (*llms.ContentResponse, error) {
	// Extract vulnerability IDs from the human message (last message)
	var vulnIDs []string
	for _, msg := range messages {
		if msg.Role == llms.ChatMessageTypeHuman {
			for _, part := range msg.Parts {
				if textPart, ok := part.(llms.TextContent); ok {
					vulnIDs = extractVulnIDs(textPart.Text)
				}
			}
		}
	}

	// Generate deterministic scores for each vulnerability
	results := make([]llmOutputEntry, 0, len(vulnIDs))
	for _, vulnID := range vulnIDs {
		scores := deterministicScores(vulnID)
		results = append(results, llmOutputEntry{
			VulnID:             vulnID,
			ThreatAgentScore:   scores[0],
			VulnerabilityScore: scores[1],
			TechnicalImpact:    scores[2],
			BusinessImpact:     scores[3],
			Reasoning:          "Mock LLM: deterministic scores for testing",
		})
	}

	output := llmOutput{Results: results}
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	// Call streaming function if provided (required by generator.go)
	opts := llms.CallOptions{}
	for _, opt := range options {
		opt(&opts)
	}
	if opts.StreamingFunc != nil {
		if err := opts.StreamingFunc(ctx, jsonBytes); err != nil {
			return nil, err
		}
	}

	return &llms.ContentResponse{
		Choices: []*llms.ContentChoice{
			{
				Content: string(jsonBytes),
			},
		},
	}, nil
}

// Call implements llms.Model (simple text interface).
func (m *MockLLM) Call(ctx context.Context, prompt string, options ...llms.CallOption) (string, error) {
	resp, err := m.GenerateContent(ctx, []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, prompt),
	}, options...)
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", nil
	}
	return resp.Choices[0].Content, nil
}

// extractVulnIDs extracts vulnerability IDs from JSON input.
var vulnIDRegex = regexp.MustCompile(`"vulnId"\s*:\s*"([^"]+)"`)

func extractVulnIDs(text string) []string {
	matches := vulnIDRegex.FindAllStringSubmatch(text, -1)
	ids := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			ids = append(ids, match[1])
		}
	}
	return ids
}

// deterministicScores generates consistent scores based on vuln ID.
// This ensures tests are reproducible.
func deterministicScores(vulnID string) [4]float64 {
	// Use a simple hash of the vulnerability ID
	hash := 0
	for _, c := range vulnID {
		hash = hash*31 + int(c)
	}

	// Extract numeric part if available (e.g., "2024" from "CVE-2024-1234")
	numRegex := regexp.MustCompile(`\d+`)
	nums := numRegex.FindAllString(vulnID, -1)
	if len(nums) > 0 {
		if n, err := strconv.Atoi(nums[len(nums)-1]); err == nil {
			hash += n
		}
	}

	// Generate 4 scores in range [3, 8] for realistic testing
	base := float64((hash % 6) + 3) // 3-8
	return [4]float64{
		clamp(base),
		clamp(base + 1),
		clamp(base - 1),
		clamp(base),
	}
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 9 {
		return 9
	}
	return v
}
