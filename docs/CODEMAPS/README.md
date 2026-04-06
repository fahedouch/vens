# Vens Codemaps & Architecture Documentation

Welcome! This directory contains comprehensive architecture documentation for the vens project.

**Last Updated:** 2026-04-05  
**Total Documentation:** 4,600+ lines across 10 files

---

## For Different Audiences

### I'm new to the project
Start here: **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)** — Get up and running in 10 minutes

### I want to understand the overall architecture
Start here: **[INDEX.md](./INDEX.md)** — Project overview, core architecture, design patterns

### I'm working on a specific area

| Area | Codemap | Key Questions |
|------|---------|---------------|
| CLI commands & flags | [cli.md](./cli.md) | How do I add a new command? How do flags work? |
| Vulnerability scoring | [generator.md](./generator.md) | How does scoring work? How are batches processed? |
| LLM integration | [llm.md](./llm.md) | How do I add a new LLM provider? |
| Scanner parsing | [scanner.md](./scanner.md) | How do I support a new scanner format? |
| Risk calculation | [owasp.md](./owasp.md) | What's the OWASP methodology? How are vectors built? |
| Config system | [configuration.md](./configuration.md) | What goes in config.yaml? How is it validated? |
| VEX generation | [output.md](./output.md) | How is the VEX document created? |
| Report enrichment | [enrichment.md](./enrichment.md) | How does `vens enrich` work? |

---

## Quick Navigation

### Understanding the Codebase

1. **Data Flow** — Read [INDEX.md → Data Flow](./INDEX.md#data-flow)
2. **Key Patterns** — Read [INDEX.md → Key Patterns](./INDEX.md#key-patterns)
3. **Testing Strategy** — Read [INDEX.md → Testing Strategy](./INDEX.md#testing-strategy)
4. **Development Setup** — Read [DEVELOPER_GUIDE.md → Quick Setup](./DEVELOPER_GUIDE.md#quick-setup)

### Making Changes

1. **Modifying CLI** → [CLI Codemap](./cli.md)
2. **Changing scoring logic** → [Generator Codemap](./generator.md) + [OWASP Codemap](./owasp.md)
3. **Adding LLM support** → [LLM Codemap](./llm.md)
4. **Adding scanner** → [Scanner Codemap](./scanner.md)
5. **Changing output format** → [Output Codemap](./output.md)
6. **Modifying config** → [Configuration Codemap](./configuration.md)

### Debugging

1. **Understanding a package** — Find its codemap
2. **Understanding test failures** — See codemap's "Testing" section
3. **Performance issues** — See codemap's "Performance" section
4. **Error messages** — See codemap's "Error Handling" section

---

## File Structure

```
docs/CODEMAPS/
├── README.md                 # This file
├── INDEX.md                  # Architecture overview & design patterns
├── DEVELOPER_GUIDE.md        # Quick-start guide for contributors
├── cli.md                    # CLI layer (Cobra commands)
├── generator.md              # Core vulnerability scoring engine
├── llm.md                    # LLM provider abstraction
├── scanner.md                # Scanner format detection & parsing
├── owasp.md                  # OWASP Risk Rating methodology
├── configuration.md          # User config.yaml system
├── output.md                 # VEX document generation
└── enrichment.md             # Report enrichment with OWASP scores
```

---

## Document Format

Each codemap follows a consistent structure:

```
# [Area] Codemap
**Last Updated:** [date]
**Package:** [go package]
**Key Files:** [important files]

## Purpose
What does this area do?

## Architecture
How is it structured? (with ASCII diagram)

## Core Types
What are the main data structures?

## Main Functions
How is it used?

## Testing
How is it tested?

## Key Design Decisions
Why were things done this way?

## See Also
Links to related codemaps
```

This consistency makes it easy to navigate and understand each area.

---

## Key Concepts

### Single Source of Truth
All documentation is generated from actual code. See comments in `.go` files.

### Freshness Timestamps
Each document includes a "Last Updated" date. If architecture changes, docs are updated.

### Token-Efficient
Each document is 400-600 lines. Long enough to be complete, short enough to fit in context.

### Actionable
Documents include setup commands, code examples, and extension patterns.

### Cross-Referenced
Related codemaps are linked. Use these to navigate between areas.

---

## How to Use These Docs

### While Coding

Keep the relevant codemap open in your editor as you work.

**Example workflow:**
```
1. Reading generator.go → Open generator.md
2. Need to understand OWASP → Open owasp.md
3. Need to add a new LLM → Open llm.md for extension pattern
4. Need to understand tests → See generator.md → Testing section
```

### While Debugging

Find the package/file you're debugging, open its codemap:

**Example:**
```
Debugging: pkg/llm/llmfactory
→ Open llm.md → Find "Factory Pattern" section
→ Read how NewLLM() works
→ Check which files handle auto-detection
```

### While Reviewing Code

Use codemaps to understand context and verify patterns:

**Example:**
```
Reviewing PR that adds new scanner
1. Open scanner.md
2. Check "Extension Points" section
3. Verify new code follows pattern
4. Check test coverage matches other scanners
```

---

## Keeping Docs Updated

When you make a code change:

1. **Update relevant codemaps** if architecture changes
2. **Update code comments** (codemaps reference them)
3. **Update timestamps** to indicate freshness
4. **Add cross-references** if linking to new areas

**Example commit:**
```
feat(llm): add gemini support

- Implement Google AI LLM provider
- Register in factory with auto-detection
- Update llm.md with provider details
- Add integration test
```

---

## Feedback & Improvements

Found an error? Want to clarify something?

1. Open an issue: "docs: improve [codemap name]"
2. Or open a PR with the fix
3. Include the reason for the change

Quality documentation is a community effort!

---

## Related Documentation

- **[README.md](../README.md)** — User-facing project overview
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** — Contributor guide (commit style, review process)
- **[docs/](../)** — Full user documentation site (MkDocs)
- **[Makefile](../../Makefile)** — Build & test automation
- **Code comments** — Docstrings in `.go` files (source of truth)

---

## Quick Reference

### Essential Commands
```bash
make binaries      # Build CLI
make test          # Run all tests
make lint          # Run linter
make fmt           # Format code
make docs          # Build docs locally
```

### Key Directories
```
cmd/vens/          # CLI entry points
pkg/               # Core packages
internal/testutil/ # Test helpers
docs/              # Documentation
examples/          # Example configs
```

### Key Files
```
cmd/vens/main.go                    # CLI entry
cmd/vens/commands/generate/generate.go
cmd/vens/commands/enrich/enrich.go
pkg/generator/generator.go          # Core engine
pkg/llm/llmfactory/llmfactory.go   # LLM selection
pkg/owasp/vector.go                # Risk calculation
```

---

## Document Statistics

| Document | Lines | Topics |
|----------|-------|--------|
| INDEX.md | 338 | Architecture, patterns, data flow |
| DEVELOPER_GUIDE.md | 409 | Quick start, common patterns |
| cli.md | 445 | Command handling, subcommands |
| generator.md | 464 | Scoring engine, LLM integration |
| llm.md | 545 | Provider abstraction, factory |
| scanner.md | 487 | Format detection, parsing |
| owasp.md | 484 | Risk methodology, calculation |
| configuration.md | 585 | Config schema, validation |
| output.md | 384 | VEX generation, output handlers |
| enrichment.md | 503 | Report enrichment, matching |
| **TOTAL** | **4,644** | Comprehensive architecture guide |

---

## Next Steps

- **New contributor?** → [DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)
- **Need architecture overview?** → [INDEX.md](./INDEX.md)
- **Working on specific feature?** → Find its codemap above
- **Have questions?** → Check the FAQ in relevant codemap

Happy coding! 🚀

