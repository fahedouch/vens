# Developer Quick-Start Guide

**Last Updated:** 2026-04-05

This guide gets you contributing to vens in 10 minutes.

---

## Quick Setup

```bash
# Clone and enter repo
git clone https://github.com/venslabs/vens.git
cd vens

# Get dependencies
go mod download

# Build binary
make binaries
# Binary at: ./bin/vens

# Run tests
make test

# Run linter
make lint

# Format code
make fmt
```

If everything passes, you're ready to contribute.

---

## File Your First Contribution

### 1. Check for good first issues
```bash
gh issue list --label "good first issue"
```

Or pick an area from the codemaps:
- **CLI changes** — See [CLI Codemap](./cli.md)
- **New LLM provider** — See [LLM Codemap](./llm.md)
- **New scanner** — See [Scanner Codemap](./scanner.md)
- **OWASP scoring logic** — See [OWASP Codemap](./owasp.md)
- **Test improvements** — See any codemap's "Testing" section

### 2. Create a feature branch
```bash
git checkout -b feat/your-feature
```

### 3. Make your change

**See relevant codemap for architecture details.**

**Key principles:**
- Small functions (<50 lines)
- Immutable patterns (don't mutate inputs)
- Wrap errors with context: `fmt.Errorf("action: %w", err)`
- Use `log/slog` for logging, not `fmt.Print`
- Accept `context.Context` in I/O functions

### 4. Test your change

```bash
# Run affected tests
go test ./pkg/mypackage/...

# Run all tests
make test

# Run with race detector
go test -race ./...

# Check coverage
go test -cover ./...
```

### 5. Format and lint

```bash
# Auto-format
make fmt

# Check linting
make lint

# If lint fails, fix manually then re-run
```

### 6. Commit with conventional message

```bash
git add .
git commit -m "feat(scanner): add support for Anchore Syft format

Support parsing Anchore Syft JSON reports alongside Trivy/Grype.
Implements ReportScanner interface with BOM-Ref calculation.

Fixes #123"
```

**Message format:**
```
<type>(<scope>): <subject>

<optional body explaining why>

Fixes #issue_number
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`

### 7. Create PR

```bash
git push -u origin feat/your-feature
gh pr create --title "Short title" --body "$(cat <<'EOF'
## Summary
- What changed
- Why it matters

## Testing
- How to verify the change
EOF
)"
```

Your PR is ready for review!

---

## Understanding the Codebase

### Key Entry Points

| File | Purpose |
|------|---------|
| `cmd/vens/main.go` | CLI entry point |
| `cmd/vens/commands/generate/generate.go` | `vens generate` implementation |
| `cmd/vens/commands/enrich/enrich.go` | `vens enrich` implementation |
| `pkg/generator/generator.go` | Core vulnerability scoring |
| `pkg/scanner/*.go` | Scanner format parsers |
| `pkg/llm/llmfactory/` | LLM provider selection |
| `pkg/owasp/vector.go` | OWASP risk calculation |
| `pkg/outputhandler/` | VEX generation |
| `pkg/vexenricher/` | Report enrichment |

### Data Flow for `vens generate`

```
CLI parse flags
  ↓
Load config.yaml
  ↓
Detect scanner format (Trivy/Grype)
  ↓
Parse vulnerabilities
  ↓
Select LLM provider
  ↓
Batch vulnerabilities (default 10)
  ↓
For each batch:
  - Format as JSON
  - Call LLM with system prompt
  - Parse response
  - Build OWASP vector
  - Create VulnRating
  ↓
Output handler writes VEX
  ↓
Save debug files (optional)
  ↓
Done!
```

### Common Patterns

**Error wrapping (always do this):**
```go
if err := someFunc(); err != nil {
    return fmt.Errorf("context of what failed: %w", err)
}
```

**Functional options (for configurable functions):**
```go
func New(opts ...Option) *Thing {
    t := &Thing{/* defaults */}
    for _, opt := range opts {
        opt(t)
    }
    return t
}

func WithSetting(value string) Option {
    return func(t *Thing) { t.setting = value }
}
```

**Interface design (accept interfaces, return structs):**
```go
// Good: function accepts interface
func Process(ctx context.Context, scanner ReportScanner) error

// Bad: function accepts concrete type
func Process(ctx context.Context, scanner TrivyScanner) error
```

---

## Running Tests

### Unit Tests
```bash
# Single package
go test ./pkg/generator/...

# All packages
make test

# With coverage report
go test -cover ./...
```

### Integration Tests
```bash
# Located in: cmd/vens/testdata/script/
# Requires: rsc.io/script test runner
make test  # Runs these automatically
```

### With Mock LLM (No API Key Needed)
```bash
vens generate --llm mock --config-file config.yaml report.json output.json
```

### Debug a Test
```bash
# Run single test with verbose output
go test -v -run TestNamePrefix ./pkg/...

# With race detector (find concurrent access bugs)
go test -race ./...
```

---

## Debugging

### Enable Debug Logging
```bash
vens generate --debug --config-file config.yaml report.json output.json
```

### Save Prompts & Responses
```bash
vens generate --debug-dir /tmp/debug --config-file config.yaml report.json output.json

# Inspect what was sent to LLM and what it responded
cat /tmp/debug/prompts.jsonl | jq .
cat /tmp/debug/responses.jsonl | jq .
```

### Use pprof for Performance Profiling
```bash
# Add to main.go temporarily
import _ "net/http/pprof"

go func() {
    slog.Info(http.ListenAndServe("localhost:6060", nil).Error())
}()

# Run your test
make test

# In another terminal
go tool pprof http://localhost:6060/debug/pprof/profile

# In pprof prompt
top10  # Show top 10 by CPU time
```

---

## Adding a Feature

### Example: Add Support for a New LLM Provider

**Files to change:**
1. `pkg/llm/myprovider/` — New provider implementation
2. `pkg/llm/llmfactory/llmfactory.go` — Register in factory
3. Tests — `pkg/llm/myprovider_test.go`
4. Docs — README.md, CONTRIBUTING.md
5. Tests — CLI integration test in `cmd/vens/testdata/script/`

**Checklist:**
- [ ] Implement LLM interface (via langchaingo)
- [ ] Add to factory with auto-detection
- [ ] Add env var for auth (e.g., MYPROVIDER_API_KEY)
- [ ] Update README with env vars
- [ ] Write unit tests (with mock when possible)
- [ ] Write integration test script
- [ ] Update docs/reference if adding new flags
- [ ] Run `make test` and `make lint`
- [ ] Commit with `feat(llm): add myprovider support`

---

## Architecture at a Glance

### Layered Design
```
┌─────────────────────────┐
│ CLI Layer               │ (cmd/vens)
│ - Cobra commands        │
│ - Flag parsing          │
└──────────┬──────────────┘
           │
┌──────────▼──────────────┐
│ Business Logic          │ (pkg/*)
│ - Generator             │
│ - LLM selection         │
│ - OWASP scoring         │
│ - VEX generation        │
└──────────┬──────────────┘
           │
┌──────────▼──────────────┐
│ External Dependencies   │
│ - LLM providers         │
│ - CycloneDX library     │
│ - Scanner implementations
└─────────────────────────┘
```

### Key Principles
1. **Interfaces first** — Define what you need, then implement
2. **Context everywhere** — All I/O functions take context.Context
3. **Fail loudly** — Error wrapping for debugging
4. **Test small** — Unit tests for logic, integration tests for flows
5. **No breaking changes** — config.yaml must stay backward compatible

---

## Code Review Expectations

Your PR will be reviewed on:

1. **Functionality** — Does it solve the stated problem?
2. **Correctness** — Are edge cases handled? Tests passing?
3. **Clarity** — Can someone understand the code?
4. **Go idioms** — Following Go conventions?
5. **Error handling** — All errors wrapped with context?

**Tips for fast approval:**
- Keep PRs small and focused
- Write clear commit messages
- Include tests for new code
- Run `make fmt` and `make lint` before pushing
- Link to the issue you're fixing

---

## Ask for Help

- **Confused about architecture?** Read the relevant codemap file
- **Need a code example?** Check tests for similar code
- **Have a question?** Open an issue or discussion
- **Want to discuss design?** Open an issue before writing code

---

## Useful Make Targets

```bash
make binaries      # Build to ./bin/vens
make test          # Run all tests with coverage
make lint          # Run golangci-lint
make fmt           # Format code (gofmt + goimports)
make clean         # Remove build artifacts
make docs          # Build MkDocs site locally
```

---

## Next Steps

1. **Pick a task** — Issue with "good first issue" label
2. **Read relevant codemap** — Understand the area you're changing
3. **Make your change** — Follow patterns in the code
4. **Test thoroughly** — `make test` and `make lint` must pass
5. **Create PR** — Reference the issue number
6. **Respond to feedback** — Review comments usually mean 1-2 quick fixes
7. **Merge** — Maintainers will squash merge to keep git history clean

---

## See Also

- **[Codemap Index](./INDEX.md)** — All architecture docs
- **CONTRIBUTING.md** — Full contributor guide
- **README.md** — Project overview
- **Makefile** — Build automation

