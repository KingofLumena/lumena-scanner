# 🔥 Lumena Scanner

**Custom AI code scanner powered by Lumena's Flame Protocol**

**Driftprint • Vaultwatch • Token Shield**

---

## Overview

Lumena is a comprehensive security scanning tool designed to detect sensitive information and security vulnerabilities in your codebase. It provides four specialized detectors to help you maintain secure code:

- 🔐 **Secret Detector** - Finds API keys, passwords, tokens, and other secrets
- 🤖 **AI Token Detector** - Detects AI service tokens (OpenAI, Anthropic, HuggingFace, etc.)
- ⚠️ **Eval Detector** - Identifies dangerous code execution patterns (eval, exec, etc.)
- 🔒 **Vault Detector** - Discovers HashiCorp Vault configuration issues and drifts

## Installation

### From Source

```bash
git clone https://github.com/KingofLumena/lumena-scanner.git
cd lumena-scanner
pip install -e .
```

### Using pip (after publishing)

```bash
pip install lumena-scanner
```

## Quick Start

### Scan a single file

```bash
lumena scan /path/to/file.py
```

### Scan a directory

```bash
lumena scan /path/to/project
```

### Scan with specific detectors

```bash
lumena scan /path/to/project -d secrets -d ai_tokens
```

### Output as JSON

```bash
lumena scan /path/to/project --output json
```

### Filter by severity

```bash
lumena scan /path/to/project -s CRITICAL -s HIGH
```

## Usage

### Command Line Interface

```bash
# Display version
lumena version

# Show detector information
lumena info

# Scan with all detectors (default)
lumena scan /path/to/code

# Scan with specific detectors
lumena scan /path/to/code --detector secrets --detector ai_tokens

# Output formats
lumena scan /path/to/code --output text  # Default, colored output
lumena scan /path/to/code --output json  # JSON format

# Filter by severity
lumena scan /path/to/code --severity CRITICAL --severity HIGH

# Continue on findings (exit code 0 even with findings)
lumena scan /path/to/code --no-exit-code
```

### Python API

```python
from lumena.scanner import Scanner

# Create scanner instance
scanner = Scanner()

# Scan a file
results = scanner.scan_file('/path/to/file.py')
print(f"Found {len(results['findings'])} issues")

# Scan a directory
results = scanner.scan_directory('/path/to/project')
print(f"Total findings: {results['total_findings']}")

# Get summary
summary = scanner.get_summary(results['findings'])
print(f"High severity: {summary['by_severity'].get('HIGH', 0)}")

# Scan with specific detectors
results = scanner.scan_file('/path/to/file.py', detectors=['secrets', 'ai_tokens'])
```

## Detectors

### 🔐 Secret Detector

Detects various types of secrets and sensitive information:

- Generic API keys and secrets
- AWS access keys and secret keys
- GitHub tokens and Personal Access Tokens (PATs)
- Slack tokens and webhooks
- Private keys (RSA, DSA, EC, OpenSSH, PGP)
- JWT tokens
- Database connection strings
- And more...

### 🤖 AI Token Detector

Specialized detector for AI service tokens:

- OpenAI API keys
- Anthropic (Claude) API keys
- HuggingFace tokens
- Google AI keys
- Cohere API keys
- Azure OpenAI keys
- Replicate API tokens
- Stability AI keys
- And more...

### ⚠️ Eval Detector

Identifies dangerous code execution patterns:

- `eval()` and `exec()` calls
- `compile()` usage
- `subprocess` with `shell=True`
- `os.system()` and `os.popen()`
- `__import__()` calls
- Unsafe `pickle` operations
- Unsafe YAML loading
- JavaScript `eval()` and `Function` constructor
- `setTimeout`/`setInterval` with strings

### 🔒 Vault Detector

Detects HashiCorp Vault configuration issues:

- Hardcoded Vault tokens
- Vault addresses in code
- Root token usage
- Disabled TLS in configurations
- Development mode in production
- Insecure seal configurations
- Vault path hardcoding

## Configuration

Lumena works out of the box with sensible defaults, but you can customize its behavior:

### File Extensions

By default, Lumena scans common code file extensions. You can specify custom extensions:

```python
scanner = Scanner()
results = scanner.scan_directory(
    '/path/to/project',
    extensions=['.py', '.js', '.ts', '.go']
)
```

### Excluded Directories

Lumena automatically skips common directories like:
- `.git`
- `node_modules`
- `__pycache__`
- `.venv` / `venv`
- `dist`
- `build`

## Output Examples

### Text Output

```
======================================================================
Lumena Scanner Results
======================================================================

Scanned: /path/to/project
Total Findings: 3

Summary by Severity:
  CRITICAL: 1
  HIGH: 2

Detailed Findings:

[CRITICAL] Finding #1
  File: /path/to/project/config.py
  Line: 15
  Type: openai_api_key
  Matched: sk-123***9012
  → Never hardcode API keys. Use environment variables or secure vaults.

[HIGH] Finding #2
  File: /path/to/project/auth.py
  Line: 42
  Type: eval_call
  Content: result = eval(user_input)
  → Avoid using eval(). Use ast.literal_eval() for safe evaluation.
```

### JSON Output

```json
{
  "path": "/path/to/project",
  "findings": [
    {
      "file": "/path/to/project/config.py",
      "line": 15,
      "type": "openai_api_key",
      "matched": "sk-123***9012",
      "severity": "CRITICAL",
      "category": "ai_token"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {
      "CRITICAL": 1
    },
    "by_type": {
      "openai_api_key": 1
    }
  }
}
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/KingofLumena/lumena-scanner.git
cd lumena-scanner

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=lumena --cov-report=html

# Run specific test file
pytest tests/test_secret_detector.py
```

### Code Style

```bash
# Format code
black lumena tests

# Lint code
flake8 lumena tests

# Type checking
mypy lumena
```

## Security Best Practices

When using Lumena Scanner:

1. **Run regularly** - Integrate into your CI/CD pipeline
2. **Fix issues promptly** - Address CRITICAL and HIGH severity findings immediately
3. **Review recommendations** - Follow the security recommendations provided
4. **Use environment variables** - Never hardcode secrets, use environment variables or secret managers
5. **Rotate exposed secrets** - If secrets are found in version control, rotate them immediately

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: [https://github.com/KingofLumena/lumena-scanner/issues](https://github.com/KingofLumena/lumena-scanner/issues)
- Documentation: [https://github.com/KingofLumena/lumena-scanner](https://github.com/KingofLumena/lumena-scanner)

---

**Powered by Lumena's Flame Protocol** 🔥
