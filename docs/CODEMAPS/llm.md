# LLM Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/pkg/llm`  
**SubPackages:** `llm/llmfactory`  
**Dependencies:** `github.com/tmc/langchaingo` (custom fork with JSON Schema support)

---

## Purpose

The LLM package provides a pluggable abstraction layer for different LLM providers (OpenAI, Anthropic, Google AI, Ollama) and test mocks. It handles authentication, model selection, rate-limit detection, and structured output enforcement.

**Inputs:** Vulnerability data + OWASP scoring prompt  
**Output:** Structured JSON with risk scores (via JSON Schema validation)

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Generator (caller)                          │
│  Wants: Chat completion with JSON Schema validation            │
└─────────────────────┬───────────────────────────────────────────┘
                      │
      ┌───────────────▼────────────────────┐
      │  LLM Factory (pkg/llm/llmfactory)  │
      │  - Detect provider from env/flag   │
      │  - Instantiate correct LLM client  │
      │  - Return langchaingo.Model        │
      └───────────────┬────────────────────┘
                      │
    ┌─────────────────┼─────────────────┬────────────────┐
    │                 │                 │                │
    ▼                 ▼                 ▼                ▼
 OpenAI         Anthropic         Google AI          Ollama
 (gpt-4o)      (claude-3.5)     (gemini-2.0)     (mistral, etc)
 via SDK       via SDK          via SDK           via HTTP
```

---

## Core Types & Constants

### Supported Backends

```go
const (
    Auto      = "auto"        // Auto-detect from environment
    OpenAI    = "openai"      // OpenAI (GPT-4, GPT-4o, etc.)
    Ollama    = "ollama"      // Ollama (local models)
    Anthropic = "anthropic"   // Anthropic (Claude family)
    GoogleAI  = "googleai"    // Google (Gemini family)
    Mock      = "mock"        // Built-in mock for testing
)

var Names = []string{OpenAI, Ollama, Anthropic, GoogleAI}
```

**Use:**
```go
// In flag help
fmt.Sprintf("LLM backend (%v)", llm.Names)
// Output: LLM backend (openai anthropic ollama googleai)
```

---

## LLM Factory: `llmfactory/`

### Purpose
Instantiate the correct LLM provider based on user selection or environment variables.

### `llmfactory.New()`

```go
func New(ctx context.Context, providerName string, opts ...Option) (llms.Model, error)
```

**How it works:**

1. **Normalize provider name**
   ```go
   if providerName == llm.Auto {
       providerName = detectProvider()
   }
   ```

2. **Validate provider**
   ```go
   if !isSupported(providerName) {
       return fmt.Errorf("unsupported provider: %s", providerName)
   }
   ```

3. **Instantiate client**
   ```go
   switch providerName {
   case llm.OpenAI:
       return newOpenAIClient(opts...)
   case llm.Anthropic:
       return newAnthropicClient(opts...)
   // ...
   }
   ```

**Options pattern:**
```go
client, err := llmfactory.New(ctx, "openai",
    llmfactory.WithModel("gpt-4o"),
    llmfactory.WithTemperature(0.0),
    llmfactory.WithSeed(42),
)
```

### Auto-Detection

Priority order (when `--llm auto`):

1. Check `OPENAI_API_KEY` environment → OpenAI
2. Check `ANTHROPIC_API_KEY` environment → Anthropic
3. Check `GOOGLE_API_KEY` environment → Google AI
4. Check `OLLAMA_MODEL` environment → Ollama
5. Fallback → error (no provider detected)

**Example:**
```bash
export OPENAI_API_KEY="sk-..."
vens generate --llm auto ...
# Auto-selects OpenAI
```

---

## Provider Implementations

### OpenAI

**Env variables:**
- `OPENAI_API_KEY` — API key (required)
- `OPENAI_MODEL` — Model name (default: gpt-4o)
- `OPENAI_BASE_URL` — Custom endpoint (optional)

**Supported models:**
- `gpt-4` — Legacy
- `gpt-4-turbo` — Latest turbo
- `gpt-4o` — Latest (recommended)
- `gpt-4o-mini` — Cheaper alternative

**Implementation:**
```go
client := openai.New(openai.WithAPIKey(apiKey))
// Returns langchaingo.Model implementing Chat interface
```

### Anthropic

**Env variables:**
- `ANTHROPIC_API_KEY` — API key (required)
- `ANTHROPIC_MODEL` — Model name (default: claude-3-5-sonnet)

**Supported models:**
- `claude-3-5-sonnet` — Latest (recommended)
- `claude-3-opus` — More capable
- `claude-3-haiku` — Cheaper

**Implementation:**
```go
client := anthropic.New(anthropic.WithAPIKey(apiKey))
```

### Google AI

**Env variables:**
- `GOOGLE_API_KEY` — API key (required)
- `GOOGLE_MODEL` — Model name (default: gemini-2.0-flash)

**Supported models:**
- `gemini-2.0-flash` — Latest (recommended)
- `gemini-pro` — Earlier version

**Implementation:**
```go
client := googleai.New(googleai.WithAPIKey(apiKey))
```

### Ollama (Local)

**Env variables:**
- `OLLAMA_MODEL` — Model name (required)
- `OLLAMA_BASE_URL` — API endpoint (default: http://localhost:11434)

**Supported models:**
- `mistral` — Fast
- `neural-chat` — Good reasoning
- Any model installed in Ollama

**Implementation:**
```go
client := ollama.New(
    ollama.WithModel(modelName),
    ollama.WithBaseURL(baseURL),
)
```

### Mock (Testing)

**How to use:**
```bash
vens generate --llm mock ...
```

**Behavior:**
- Deterministic responses
- No external API calls
- Perfect for integration tests

**Response format:**
```json
{
  "vulnId": "CVE-XXXX-YYYY",
  "threat_agent_score": 5,
  "vuln_factor_score": 6,
  "technical_impact": 7,
  "business_impact": 6,
  "reasoning": "Mock LLM response"
}
```

**Location:** `internal/testutil/mockllm.go`

---

## JSON Schema Enforcement

### Why JSON Schema?

Traditional approaches:
- Regex parsing → brittle, error-prone
- Prompt engineering tricks → unreliable hallucination
- Post-processing → still need validation

**langchaingo with JSON Schema:**
- Native support (via structured output API)
- LLM respects schema constraints
- Guaranteed parseable output
- No hallucination outside schema

### Custom Fork

Vens uses a custom fork of langchaingo:
```go
module github.com/tmc/langchaingo
// go.mod
replace github.com/tmc/langchaingo => 
    github.com/AkihiroSuda/langchaingo v0.0.0-20250606094520-...
```

**Why custom fork?**
- Adds JSON Schema parameter support
- Allows Ollama to enforce structured output
- Upstream PR in progress

### Schema Definition

```go
type llmOutputEntry struct {
    VulnID             string  `json:"vulnId"`
    ThreatAgentScore   float64 `json:"threat_agent_score"`
    VulnFactorScore    float64 `json:"vuln_factor_score"`
    TechnicalImpact    float64 `json:"technical_impact"`
    BusinessImpact     float64 `json:"business_impact"`
    Reasoning          string  `json:"reasoning"`
}
```

**Converted to JSON Schema:**
```json
{
  "type": "object",
  "properties": {
    "vulnId": { "type": "string" },
    "threat_agent_score": { "type": "number", "minimum": 0, "maximum": 9 },
    ...
  },
  "required": ["vulnId", "threat_agent_score", ...]
}
```

**Generator usage:**
```go
// When calling LLM with schema
resp := client.GenerateContent(ctx,
    llms.MessageContent{
        Parts: []llms.ContentPart{
            llms.TextContent{
                Text: systemPrompt,
            },
            llms.TextContent{
                Text: vulnJSON,
            },
        },
    },
    llms.WithJSONSchema(schema),  // Custom langchaingo extension
)
```

---

## Rate Limit Handling

### Detection: `isRateLimit()`

```go
func isRateLimit(err error) bool
```

**Detects:**
- HTTP 429 status codes
- Provider-specific rate-limit errors
- Heuristic: "429" + "rate" in error message

**Examples:**
```
"status code: 429" → true
"Error 429: Rate limit exceeded" → true
"quota exceeded" → false (need more detection logic)
```

### Retry Logic: `RetryOnRateLimit()`

```go
func RetryOnRateLimit(ctx context.Context, interval time.Duration, 
    maxRetry int, fn func(context.Context) error) error
```

**How it works:**

1. Try to call function
2. If not rate limit → return immediately
3. If rate limit:
   - Sleep for interval
   - Increment retry counter
   - Try again
4. If still hitting limit after maxRetry → return error

**Example:**
```go
err := llm.RetryOnRateLimit(ctx, 10*time.Second, 10, func(ctx context.Context) error {
    return generator.Generate(ctx)
})

// Behavior:
// - If 429: sleep 10s, retry
// - If 429 again: sleep 10s, retry
// - Up to 10 times
// - After 10 retries: return error
```

**Configuration:**
```go
const (
    DefaultSleepOnRateLimit = 10 * time.Second
    DefaultRetryOnRateLimit = 10
)
```

**User override (from CLI):**
```bash
# No CLI flags currently, but could add:
# vens generate --llm-rate-limit-interval 5s --llm-rate-limit-retries 20
```

---

## Integration with Generator

### Calling Pattern

```go
// In generate command action
llmClient, err := llmfactory.New(ctx, llmProvider,
    llmfactory.WithModel(model),
    llmfactory.WithTemperature(temperature),
    llmfactory.WithSeed(seed),
)

// In generator.Generate()
vulns, err := generator.Generate(ctx,
    WithLLM(llmClient),
    WithBatchSize(batchSize),
)
```

### Timeout Control

Generator is context-aware:
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

vulns, err := generator.Generate(ctx, ...)
// If LLM takes >5 minutes, context cancels and returns error
```

---

## Error Handling & Recovery

### Common Errors

| Error | Cause | Recovery |
|-------|-------|----------|
| 401 Unauthorized | Wrong API key | Check env var, rotate key |
| 429 Too Many Requests | Rate limit | Retry with backoff |
| 500 Internal Server Error | Provider outage | Retry or wait |
| Connection timeout | Network issue | Retry with backoff |
| Invalid schema | JSON doesn't match | Debug with `--debug-dir` |

### Debug Mode

When `--debug-dir` is set:

**Saved files:**
- `prompts.jsonl` — System prompt + batch request
- `responses.jsonl` — Raw LLM response JSON
- `parsed_output.json` — After JSON parse
- `timing.json` — API call duration

**Example:**
```bash
vens generate --debug-dir /tmp/debug ...
cat /tmp/debug/responses.jsonl | jq .
```

---

## Testing

### Unit Tests

```go
func TestDetectProvider(t *testing.T) {
    t.Setenv("OPENAI_API_KEY", "test-key")
    provider := detectProvider()
    assert.Equal(t, llm.OpenAI, provider)
}
```

### Integration Tests

Use mock LLM:
```bash
vens generate --llm mock --config-file config.yaml report.json output.json
```

No API keys needed, deterministic output.

---

## Configuration

### Environment Variables

| Variable | Provider | Purpose | Example |
|----------|----------|---------|---------|
| `OPENAI_API_KEY` | OpenAI | Authentication | `sk-...` |
| `OPENAI_MODEL` | OpenAI | Model selection | `gpt-4o` |
| `ANTHROPIC_API_KEY` | Anthropic | Authentication | `sk-ant-...` |
| `ANTHROPIC_MODEL` | Anthropic | Model selection | `claude-3-5-sonnet` |
| `GOOGLE_API_KEY` | Google AI | Authentication | `AIza...` |
| `GOOGLE_MODEL` | Google AI | Model selection | `gemini-2.0-flash` |
| `OLLAMA_MODEL` | Ollama | Model name | `mistral` |
| `OLLAMA_BASE_URL` | Ollama | API endpoint | `http://localhost:11434` |

### CLI Flags

From `cmd/vens/commands/generate/generate.go`:

```bash
--llm {auto|openai|anthropic|ollama|googleai|mock}
--llm-temperature 0.0  # 0 = deterministic
--llm-seed 42          # Reproducibility (provider dependent)
--llm-batch-size 10    # CVEs per request
```

---

## Adding a New LLM Provider

### Steps

1. **Create provider implementation**
   ```go
   // pkg/llm/newprovider.go
   func New(apiKey string, opts ...Option) llms.Model
   ```

2. **Add to factory**
   ```go
   // pkg/llm/llmfactory/llmfactory.go
   case "newprovider":
       return newNewProviderClient(opts...)
   ```

3. **Add detection**
   ```go
   // In detectProvider()
   if apiKey := os.Getenv("NEWPROVIDER_API_KEY"); apiKey != "" {
       return "newprovider"
   }
   ```

4. **Update docs**
   - README.md (env variables)
   - CONTRIBUTING.md (testing)
   - Inline code comments

5. **Add tests**
   - Unit tests in `llmfactory_test.go`
   - Integration tests in `cmd/vens/testdata/script/`

---

## Performance Characteristics

| Provider | Latency | Cost | Token Limit |
|----------|---------|------|------------|
| OpenAI gpt-4o | 2-5s | $$ | 128k |
| Anthropic Claude 3.5 | 1-3s | $ | 200k |
| Google Gemini 2.0 | 1-2s | $ | 1M |
| Ollama local | <1s | Free | Model dependent |

**Recommendation:** Start with OpenAI for reliability, switch to Anthropic for cost.

---

## See Also

- **[Generator Codemap](./generator.md)** — Invokes LLM via factory
- **[CLI Codemap](./cli.md)** — Passes LLM provider from flags
- **CONTRIBUTING.md** — Testing with mock LLM
- **langchaingo documentation** — SDK details

