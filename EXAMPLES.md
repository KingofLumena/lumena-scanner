# Example Usage and Testing

This directory contains examples demonstrating Lumena Scanner's capabilities.

## Running the Examples

### 1. Basic Python API Usage

```bash
python3 examples/example_usage.py
```

This demonstrates:
- Scanning a single file
- Getting summary statistics
- Scanning with specific detectors
- Scanning directories

### 2. CLI Usage Examples

```bash
# Scan a file with all detectors
lumena scan examples/vulnerable_code.py

# Scan with specific detectors
lumena scan examples/vulnerable_code.py -d secrets -d ai_tokens

# Output as JSON
lumena scan examples/vulnerable_code.py --output json

# Filter by severity
lumena scan examples/vulnerable_code.py -s CRITICAL -s HIGH

# Show scanner information
lumena info

# Display version
lumena version
```

## Test Files

The `test_sample.py` file contains intentional security issues for testing:
- API keys and secrets
- AI service tokens
- Dangerous eval/exec calls
- Vault configuration issues

## False Positives Note

When scanning the Lumena source code itself, you may see findings in the detector modules. These are expected because:

1. The detector files contain regex patterns that match what they're looking for
2. Documentation strings describe dangerous patterns (e.g., "eval() calls")
3. Test files contain intentional security issues

This demonstrates that the scanner is thorough and catches all pattern matches. In a production environment, you can:

- Use `.lumenaignore` files to exclude certain paths (future feature)
- Filter findings by file patterns in your CI/CD pipeline
- Review findings manually to identify false positives

## Integration Examples

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Lumena
        run: pip install lumena-scanner
      - name: Run Lumena Scanner
        run: lumena scan . --output json > scan-results.json
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan
          path: scan-results.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running Lumena Scanner..."
lumena scan $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|js|ts|go)$')

if [ $? -ne 0 ]; then
    echo "Security issues found! Please fix before committing."
    exit 1
fi
```

### Python Script Integration

```python
from lumena.scanner import Scanner
import sys

scanner = Scanner()
results = scanner.scan_directory('src/')

# Check for critical issues
critical_findings = [
    f for f in results['findings'] 
    if f.get('severity') == 'CRITICAL'
]

if critical_findings:
    print(f"❌ Found {len(critical_findings)} critical security issues!")
    for finding in critical_findings:
        print(f"  {finding['file']}:{finding['line']} - {finding['type']}")
    sys.exit(1)
else:
    print("✅ No critical security issues found")
    sys.exit(0)
```
