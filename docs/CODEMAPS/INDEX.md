# Vens Codemap Index

**Last Updated:** 2026-04-05

A complete architectural map of the vens codebase for contributors and maintainers.

---

## Overview

Vens is a context-aware vulnerability risk scoring CLI tool that transforms generic CVSS scores into contextual OWASP risk scores using LLM intelligence. It outputs standards-compliant CycloneDX VEX documents.

**Repository Structure:**
```
vens/
├── cmd/vens/                 # CLI entry point and commands
├── pkg/                      # Core business logic packages
├── internal/testutil/        # Test utilities and mock LLM
├── docs/                     # MkDocs documentation site
├── examples/                 # Example configs and test data
├── Makefile                  # Build and development targets
└── mkdocs.yml               # MkDocs configuration
```

---

## Core Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          CLI Layer (cmd/vens)                           │
│  ┌──────────────────────┐              ┌──────────────────────┐        │
│  │ generate             │              │ enrich               │        │
│  │ - Parse config       │              │ - Apply VEX scores   │        │
│  │ - Invoke generator   │              │ - Enrich reports     │        │
│  └──────────────────────┘              └──────────────────────┘        │
└───────────────────┬──────────────────────────────────────┬──────────────┘
                    │                                      │
        ┌───────────▼──────────────┐        ┌──────────────▼──────┐
        │  Generator               │        │  VEX Enricher      │
        │  (pkg/generator)         │        │  (pkg/vexenricher) │
        │ - Parse input reports    │        │ - Match VEX scores │
        │ - Invoke LLM             │        │ - Merge into report│
        │ - Generate VEX output    │        └────────────────────┘
        └───────────┬──────────────┘
                    │
        ┌───────────▼─────────────────────────────────┐
        │  Core Dependencies                          │
        ├─────────────────────────────────────────────┤
        │  • Scanner (trivy/grype format detection)   │
        │  • LLM Factory (OpenAI/Anthropic/etc.)      │
        │  • Risk Config (config.yaml parsing)        │
        │  • OWASP Vector (risk calculation)          │
        │  • Output Handler (VEX generation)          │
        └─────────────────────────────────────────────┘
```

---

## Codemaps by Area

### 1. CLI & Command Handling
**[→ Open: CLI Codemap](./cli.md)**

Handles command-line interface using Cobra framework.

- Entry point: `cmd/vens/main.go`
- Commands: `generate` and `enrich` subcommands
- Flag parsing and LLM provider selection
- Version management

---

### 2. Core Vulnerability Processing
**[→ Open: Generator Codemap](./generator.md)**

The heart of the system — transforms scanner reports to risk-scored VEX documents.

- Input format detection (Trivy/Grype)
- LLM-based risk scoring
- Batch processing and rate-limit handling
- Output handler pipeline

---

### 3. LLM Integration
**[→ Open: LLM Codemap](./llm.md)**

Multi-provider LLM support with automatic detection and fallback.

- Provider factories: OpenAI, Anthropic, Ollama, Google AI
- Rate-limit handling and retry logic
- JSON schema enforcement for structured output
- Mock LLM for testing

---

### 4. Scanner Support
**[→ Open: Scanner Codemap](./scanner.md)**

Pluggable parsers for different vulnerability scanner formats.

- Format detection (Trivy/Grype)
- BOM-Ref calculation
- Source mapping (NVD, vendor sources)
- Common vulnerability representation

---

### 5. Risk Calculation & OWASP
**[→ Open: OWASP Codemap](./owasp.md)**

OWASP Risk Rating methodology implementation.

- 16-factor vector calculation
- Score aggregation (Threat Agent, Vulnerability, Technical Impact, Business Impact)
- Severity classification
- Vector string generation

---

### 6. Configuration Management
**[→ Open: Configuration Codemap](./configuration.md)**

User-facing context configuration system.

- YAML schema parsing
- Validation and defaults
- Context factors (exposure, data sensitivity, business criticality)
- Compliance requirements

---

### 7. Output & VEX Generation
**[→ Open: Output Codemap](./output.md)**

Standards-compliant CycloneDX VEX document generation.

- VEX document structure
- Rating embedding
- BOM-Link management
- Debug file export

---

### 8. VEX Enrichment
**[→ Open: Enrichment Codemap](./enrichment.md)**

Applying generated scores back to original scanner reports.

- Score matching by Vulnerability ID
- Report mutation and output
- Format preservation

---

---

## Key Patterns

### 1. **Functional Options Pattern** (Generator, OutputHandler)
Used for extensible, configuration-heavy operations.

```go
func New(opts ...Option) *Generator {
    g := &Generator{/* defaults */}
    for _, opt := range opts {
        opt(g)
    }
    return g
}
```

### 2. **Interface-Based Abstraction** (ReportScanner, OutputHandler, LLM)
Enables swappable implementations without coupling to specific libraries.

```go
type ReportScanner interface {
    Parse(data []byte) ([]Vulnerability, error)
    Name() string
}
```

### 3. **Factory Pattern** (LLM, Scanner)
Dynamic provider selection based on runtime configuration.

```go
func New(providerName string) (LLM, error) {
    switch providerName {
    case "openai": return &OpenAILLM{}, nil
    // ...
    }
}
```

### 4. **Pipeline Pattern** (Generator → OutputHandler)
Streaming vulnerability processing through structured handlers.

---

## Data Flow

### `vens generate` Command Flow

```
1. Parse CLI flags
2. Load config.yaml (user context)
3. Detect scanner format (Trivy/Grype)
4. Parse vulnerability report
5. Select LLM provider
6. For each batch of vulnerabilities:
   - Format as JSON with LLM schema
   - Send to LLM with system prompt
   - Parse LLM response
   - Calculate OWASP vector
   - Create CycloneDX VEX entry
7. Write VEX output file
8. Log debug data (optional)
```

### `vens enrich` Command Flow

```
1. Load generated VEX file
2. Extract OWASP scores by Vulnerability ID
3. Load original Trivy/Grype report
4. Match scores to vulnerabilities
5. Add OWASP ratings to each vulnerability
6. Write enriched report to output
```

---

## Testing Strategy

**Test Organization:**
- Unit tests colocated: `*_test.go` files
- Integration tests: `cmd/vens/testdata/script/` (rsc.io/script format)
- Mock LLM: `internal/testutil/mockllm.go`

**Coverage Goal:** 80%+

**Key Test Files:**
- Scanner tests: `pkg/scanner/*_test.go`
- Generator tests: `pkg/generator/*_test.go`
- Output handler tests: `pkg/outputhandler/*_test.go`
- CLI script tests: `cmd/vens/testdata/script/`

---

## Development Workflow

### Setup
```bash
git clone github.com/venslabs/vens
cd vens
go mod download
make binaries  # Build to ./bin/
make test      # Full test suite
make lint      # golangci-lint checks
make fmt       # gofmt + goimports
```

### Key Make Targets
- `make binaries` — Build CLI binary
- `make test` — Run all tests with coverage
- `make lint` — Run static analysis
- `make fmt` — Format code
- `make docs` — Build MkDocs site locally

### Before Opening a PR
1. Run `make test` — all tests must pass
2. Run `make lint` — all linting must pass
3. Run `make fmt` — code must be properly formatted
4. Commit with conventional-commits style (`feat(...)`, `fix(...)`, `docs(...)`)
5. Link issues with `Fixes #NNN` or `Refs #NNN`

---

## External Dependencies

### Key Libraries

| Package | Purpose | Version |
|---------|---------|---------|
| `github.com/CycloneDX/cyclonedx-go` | VEX document generation | v0.10.0 |
| `github.com/spf13/cobra` | CLI framework | v1.10.2 |
| `github.com/tmc/langchaingo` | LLM abstraction (custom fork for JSON Schema) | v0.0.0-20250606... |
| `github.com/aquasecurity/trivy` | Trivy format reference | v0.69.3 |
| `github.com/anchore/grype` | Grype format reference | v0.110.0 |
| `go.yaml.in/yaml/v3` | YAML parsing | v3.0.4 |

### LLM Providers Supported

- **OpenAI** — via `github.com/tmc/langchaingo` (GPT-4, GPT-4o)
- **Anthropic** — via `github.com/tmc/langchaingo` (Claude family)
- **Google AI** — via `github.com/tmc/langchaingo` (Gemini)
- **Ollama** — via `github.com/tmc/langchaingo` (Local models)
- **Mock** — Built-in for testing

---

## Environment Variables

| Variable | Purpose | Required | Example |
|----------|---------|----------|---------|
| `OPENAI_API_KEY` | OpenAI authentication | With OpenAI provider | `sk-...` |
| `OPENAI_MODEL` | OpenAI model selection | With OpenAI provider | `gpt-4o` |
| `ANTHROPIC_API_KEY` | Anthropic authentication | With Anthropic provider | `sk-ant-...` |
| `GOOGLE_API_KEY` | Google AI authentication | With Google AI provider | `AIza...` |
| `OLLAMA_MODEL` | Ollama model name | With Ollama provider | `mistral` |
| `DEBUG` | Enable debug logging | No | `true` |

---

## Common Questions

**Q: How do I add a new LLM provider?**
A: Implement the LLM interface in `pkg/llm/` and register in `pkg/llm/llmfactory/`. See OpenAI implementation as reference.

**Q: How do I add support for a new scanner format?**
A: Implement `ReportScanner` interface in `pkg/scanner/` with format-specific parsing logic.

**Q: How do I add a new output format?**
A: Implement `OutputHandler` interface in `pkg/outputhandler/`.

**Q: How do I test without a real LLM API key?**
A: Use the mock LLM: set `--llm mock` flag. Integration tests use this by default.

---

## Further Reading

- **README.md** — User-facing project overview
- **CONTRIBUTING.md** — Contributor guide with code standards
- **docs/** — Full MkDocs documentation site
- Individual codemap files — Deep dives into specific areas

