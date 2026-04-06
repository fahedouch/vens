# CLI Codemap

**Last Updated:** 2026-04-05  
**Package:** `github.com/venslabs/vens/cmd/vens`  
**Entry Point:** `main.go`  
**Framework:** Cobra v1.10.2

---

## Purpose

The CLI layer provides user-facing commands using the Cobra framework. It handles:
- Command parsing and validation
- Flag management
- Error reporting
- Version display
- Subcommand routing

---

## Architecture

```
┌──────────────────────────────────────────┐
│        main()                            │
│  - Configure logging (slog)              │
│  - Build root command                    │
│  - Execute and report errors             │
└─────────────────┬────────────────────────┘
                  │
      ┌───────────▼──────────────┐
      │ Root Command (vens)      │
      │ - Version                │
      │ - Debug flag             │
      │ - Subcommand router      │
      └───────────┬──────────────┘
                  │
      ┌───────────┴──────────────┬──────────────┐
      │                          │              │
      ▼                          ▼              ▼
   generate              enrich            (extensible)
   (generate.New())      (enrich.New())
```

---

## Main Entry Point: `main.go`

```go
func main() {
    // Setup slog text handler on stderr
    logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
        Level: logLevel, // Controlled by --debug flag
    })
    slog.SetDefault(slog.New(logHandler))
    
    // Execute root command
    if err := newRootCommand().Execute(); err != nil {
        slog.Error("Error", "error", err)
        os.Exit(1)
    }
}
```

**Key points:**
- Logging uses structured `log/slog` (not log.Printf)
- Errors logged before exit
- Exit code 1 on any error

---

## Root Command Structure

```go
func newRootCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:           "vens",
        Short:         "Evaluate and prioritize vulnerabilities based on context",
        Example:       generate.Example(),
        Version:       version.GetVersion(),
        Args:          cobra.NoArgs,
        SilenceUsage:  true,
        SilenceErrors: true,
    }
    
    // Persistent flags (available to all subcommands)
    flags := cmd.PersistentFlags()
    flags.Bool("debug", envutil.Bool("DEBUG", false), "debug mode [$DEBUG]")
    
    // Pre-run hook sets log level
    cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
        if debug, _ := cmd.Flags().GetBool("debug"); debug {
            logLevel.Set(slog.LevelDebug)
        }
        return nil
    }
    
    // Register subcommands
    cmd.AddCommand(
        generate.New(),
        enrich.New(),
    )
    
    return cmd
}
```

**Design notes:**
- `SilenceUsage: true` — Don't print usage on error (confusing)
- `SilenceErrors: true` — We handle error printing ourselves
- `PersistentPreRunE` — Runs before any subcommand

---

## Subcommand 1: `generate`

### Location
`cmd/vens/commands/generate/generate.go`

### Function
Generates CycloneDX VEX with OWASP risk scores from a scanner report.

### Usage
```bash
vens generate [flags] INPUT OUTPUT
```

### Arguments
- `INPUT` — Path to Trivy or Grype JSON report
- `OUTPUT` — Path for VEX output file

### Flags

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `--config-file` | string | "" | Path to config.yaml (required) |
| `--llm` | string | "auto" | LLM provider: openai, anthropic, ollama, googleai, auto, mock |
| `--llm-temperature` | float64 | 0.0 | Temperature for LLM (0 = deterministic) |
| `--llm-batch-size` | int | 10 | Vulnerabilities per LLM request |
| `--llm-seed` | int | 0 | Seed for reproducible output (provider dependent) |
| `--input-format` | string | "auto" | trivy, grype, auto |
| `--output-format` | string | "auto" | cyclonedxvex (only option currently) |
| `--debug-dir` | string | "" | Directory to save prompts/responses for debugging |
| `--sbom-serial-number` | string | "" | SBOM serial number (urn:uuid:...) for BOM-Link |
| `--sbom-version` | int | 1 | SBOM version for BOM-Link |

### Action Function

```go
func action(cmd *cobra.Command, args []string) error
```

**Flow:**
1. Parse and validate flags
2. Load input report file
3. Load config.yaml file
4. Create scanner (detect format or use explicit)
5. Parse vulnerabilities
6. Create LLM provider (detect or use explicit)
7. Create output handler
8. Invoke generator with all options
9. Write output file
10. Return error if any step fails

### Example

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o"

trivy image python:3.11 --format json > report.json

vens generate \
    --config-file config.yaml \
    --sbom-serial-number "urn:uuid:$(uuidgen)" \
    report.json output.vex.json
```

---

## Subcommand 2: `enrich`

### Location
`cmd/vens/commands/enrich/enrich.go`

### Function
Enriches original scanner report with OWASP scores from a VEX file.

### Usage
```bash
vens enrich [flags] INPUT OUTPUT
```

### Arguments
- `INPUT` — Path to Trivy JSON report
- `OUTPUT` — Path for enriched report output

### Flags

| Flag | Type | Default | Purpose |
|------|------|---------|---------|
| `--vex` | string | "" | Path to VEX file from `vens generate` (required) |
| `--debug` | bool | false | Enable debug logging |

### Action Function

**Flow:**
1. Load VEX file
2. Load input Trivy report
3. Create VEXEnricher from VEX data
4. Enrich report (match scores by Vulnerability ID)
5. Write enriched report to output file
6. Return error if any step fails

### Example

```bash
# After running generate
vens generate --config-file config.yaml report.json output.vex.json

# Now enrich the original report
vens enrich --vex output.vex.json report.json enriched_report.json

# enriched_report.json now has OWASP ratings for each CVE
```

---

## Subcommand Extension Pattern

To add a new command:

1. Create package under `cmd/vens/commands/mycommand/`
2. Implement `New() *cobra.Command` function
3. Implement action function with your logic
4. Register in root command: `cmd.AddCommand(mycommand.New())`

**Example template:**
```go
package mycommand

import "github.com/spf13/cobra"

func New() *cobra.Command {
    cmd := &cobra.Command{
        Use:     "mycommand INPUT OUTPUT",
        Short:   "Do something useful",
        Args:    cobra.ExactArgs(2),
        RunE:    action,
    }
    
    flags := cmd.Flags()
    flags.String("my-flag", "default", "Description")
    
    return cmd
}

func action(cmd *cobra.Command, args []string) error {
    input := args[0]
    output := args[1]
    // Your logic here
    return nil
}
```

---

## Error Handling

**Strategy:** Fail fast with clear messages.

**Error message format:**
```
slog.Error("Operation failed", "error", err, "context_key", context_value)
```

**Example:**
```go
if err := loadConfig(configPath); err != nil {
    return fmt.Errorf("failed to load config.yaml from %s: %w", configPath, err)
}
```

**Exit codes:**
- `0` — Success
- `1` — Any error (missing args, file I/O, LLM error, validation error)

---

## Version Management

**Location:** `cmd/vens/version/version.go`

**Get version:**
```go
version.GetVersion()
```

**Version sources (priority order):**
1. Build-time `-ldflags` (set by `make binaries`)
2. Git describe (if built from git)
3. "dev" (default for local development)

**Usage:**
```bash
vens --version
```

---

## Environment Variable Integration

The CLI respects environment variables for defaults:

| Flag | Environment Variable | Priority |
|------|----------------------|----------|
| `--debug` | `DEBUG` | CLI flag > env var > default (false) |
| `--llm` | `LLM` (inferred) | CLI flag > auto-detect from env |
| `--llm-temperature` | `LLM_TEMPERATURE` | CLI flag > env var |

**Pattern (from envutil package):**
```go
flags.Bool("debug", envutil.Bool("DEBUG", false), "debug mode [$DEBUG]")
```

This shows the env var name in help text and uses it as default.

---

## Flag Validation

Each command validates its flags before action:

```go
func action(cmd *cobra.Command, args []string) error {
    // Parse flags
    configPath, _ := cmd.Flags().GetString("config-file")
    if configPath == "" {
        return fmt.Errorf("--config-file is required")
    }
    
    // Validate input file exists
    if _, err := os.Stat(args[0]); err != nil {
        return fmt.Errorf("input file not found: %w", err)
    }
    
    // Continue...
}
```

---

## Cobra Best Practices Used

| Practice | Implementation | Benefit |
|----------|-----------------|---------|
| Persistent flags | Root-level `--debug` | Available to all commands |
| Args validation | `cobra.ExactArgs(2)` | Fail before action runs |
| PreRunE hook | Global log level setup | One place to configure logging |
| Error silencing | `SilenceUsage: true` | Avoid duplicate output |
| Examples in help | `Example: generate.Example()` | Self-documenting |
| Short descriptions | 1-line Short field | Fast help understanding |

---

## Testing

### Unit Tests
- Flag parsing: `generate_test.go`, `enrich_test.go`
- Action functions with mock inputs

### Integration Tests
Located in `cmd/vens/testdata/script/` using `rsc.io/script` format:

**Example script test:**
```
# Test: Basic generate command
env OPENAI_API_KEY=test
exec vens generate --config-file config.yaml --llm mock input.json output.json
stdout 'generated'
! stderr 'error'
```

**Run scripts:**
```bash
make test  # Runs all script tests
```

---

## Help Text Examples

```bash
# Root help
$ vens --help
Evaluate and prioritize vulnerabilities based on context

Usage:
  vens [command]

Available Commands:
  generate    Generate CycloneDx VEX with OWASP risk scores using LLM
  enrich      Apply VEX scores to your Trivy report
  help        Help about any command

Flags:
  --debug       debug mode [$DEBUG]
  -h, --help    help for vens
  --version     version for vens

Use "vens [command] --help" for more information about a command.

# Generate command help
$ vens generate --help
Generate Vulnerability-Exploitability eXchange (VEX) information using an LLM...

Usage:
  vens generate [flags] INPUT OUTPUT

Flags:
  --config-file string             Path to config.yaml file
  --llm string                     LLM backend (openai|anthropic|ollama|googleai|auto|mock)
  --llm-batch-size int             LLM batch size (default 10)
  --debug-dir string               Directory to save debug files
  
Enrich help
$ vens enrich --help
Apply VEX scores to your Trivy report

Usage:
  vens enrich [flags] INPUT OUTPUT

Flags:
  --vex string                     Path to VEX file from vens generate
```

---

## See Also

- **[Generator Codemap](./generator.md)** — The core logic invoked by `generate`
- **[VEX Enrichment Codemap](./enrichment.md)** — The logic invoked by `enrich`
- **CONTRIBUTING.md** — Command standards and conventions
- **Makefile** — Build targets

