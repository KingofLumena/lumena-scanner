# 🚀 Quick Start Guide

Get started with Lumena Scanner in under 5 minutes!

## Installation

```bash
# Clone the repository
git clone https://github.com/KingofLumena/lumena-scanner.git
cd lumena-scanner

# Install the package
pip install -e .
```

## Your First Scan

### 1. Scan a single file

```bash
lumena scan your_file.py
```

### 2. Scan a directory

```bash
lumena scan ./src
```

### 3. Scan with specific detectors

```bash
# Only check for AI tokens
lumena scan ./src -d ai_tokens

# Check for secrets and eval calls
lumena scan ./src -d secrets -d eval
```

## Understanding the Output

Lumena reports findings with the following information:

- **File**: Path to the file with the issue
- **Line**: Line number where the issue was found
- **Type**: Type of security issue detected
- **Severity**: CRITICAL, HIGH, MEDIUM, or LOW
- **Matched**: Masked value of what was found
- **Recommendation**: How to fix the issue

Example output:
```
[CRITICAL] Finding #1
  File: /path/to/config.py
  Line: 15
  Type: openai_api_key
  Matched: sk-123***9012
  → Never hardcode API keys. Use environment variables or secure vaults.
```

## Common Use Cases

### Scan before committing code

```bash
# Scan only changed files
git diff --name-only | xargs lumena scan
```

### CI/CD Integration

```bash
# Scan and fail build if issues found
lumena scan . --exit-code

# Continue build even with issues
lumena scan . --no-exit-code
```

### Filter by severity

```bash
# Only show critical and high severity issues
lumena scan . -s CRITICAL -s HIGH
```

### Export results

```bash
# Get JSON output for parsing
lumena scan . --output json > scan-results.json
```

## Available Detectors

| Detector | Flag | What it detects |
|----------|------|-----------------|
| **Secret Detector** | `secrets` | API keys, passwords, AWS keys, GitHub tokens, private keys |
| **AI Token Detector** | `ai_tokens` | OpenAI, Anthropic, HuggingFace, Google AI keys |
| **Eval Detector** | `eval` | eval(), exec(), subprocess shell=True, os.system() |
| **Vault Detector** | `vault` | Vault tokens, disabled TLS, dev mode |

## Quick Tips

1. **Start with all detectors**: Run without `-d` flag to scan everything
2. **Focus on CRITICAL**: Use `-s CRITICAL` to see the most urgent issues first
3. **Use JSON output**: Great for integrating with other tools
4. **Regular scans**: Run before every commit or in CI/CD
5. **Fix incrementally**: Start with CRITICAL, then HIGH, then MEDIUM

## Getting Help

```bash
# Show all available commands
lumena --help

# Show information about detectors
lumena info

# Show version
lumena version

# Get help on scan command
lumena scan --help
```

## Python API Quick Example

```python
from lumena.scanner import Scanner

# Create scanner
scanner = Scanner()

# Scan a file
results = scanner.scan_file('config.py')

# Check for critical issues
critical = [f for f in results['findings'] if f['severity'] == 'CRITICAL']
if critical:
    print(f"⚠️  Found {len(critical)} critical issues!")
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [EXAMPLES.md](EXAMPLES.md) for integration examples
- See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

## Common Issues

### "Command not found: lumena"

Make sure you installed the package:
```bash
pip install -e .
```

Or add to your PATH:
```bash
export PATH="$PATH:$HOME/.local/bin"
```

### "No findings" on files with issues

Check that:
1. File extensions are supported (`.py`, `.js`, `.ts`, etc.)
2. Files aren't in excluded directories (`.git`, `node_modules`, etc.)
3. Patterns match your secret format

### Too many false positives

This is common with static analysis. You can:
1. Review findings manually
2. Focus on CRITICAL severity first
3. Use specific detectors instead of scanning everything

---

**Ready to secure your code?** Start scanning now! 🔥

```bash
lumena scan .
```
