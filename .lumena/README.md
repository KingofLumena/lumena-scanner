# Lumena Scanner

AI-powered security code scanner that detects secrets, API keys, AI drift signatures, and dangerous function calls.

## Components

### Core Scanner (`scan.py`)
Main orchestrator that coordinates all detectors and generates reports.

### Detectors

#### 1. Vaultwatch (Secret Detection)
Detects leaked secrets and credentials:
- AWS Access Keys and Secret Keys
- GitHub Tokens (PAT, OAuth)
- Generic API Keys and Tokens
- Private Keys (RSA, EC, DSA)
- Passwords in code
- Slack Tokens
- Google API Keys
- Stripe API Keys
- JWT Tokens
- Database connection strings

#### 2. Flame Overlay (AI Drift Detection)
Identifies AI-related security risks:
- AI-generated code signatures
- AI instruction leaks
- Prompt injection attempts
- Model override attempts
- Suspicious eval patterns

#### 3. Echo Anomaly (Dangerous Functions)
Detects unsafe code patterns:
- Python: `eval()`, `exec()`, `pickle`, `os.system()`
- JavaScript: `eval()`, `Function()`, `innerHTML`, `document.write()`
- Shell command injection
- SQL injection risks
- Debug mode enabled
- Disabled SSL verification

## Usage

### Run Locally
```bash
python .lumena/scan.py
```

### Run via GitHub Actions
The scanner runs automatically on every push and pull request.

## Architecture

The scanner uses a modular architecture based on the `BaseDetector` abstract class:

```python
class BaseDetector(ABC):
    def scan_file(self, file_path: str, content: str) -> List[Finding]
    def should_scan_file(self, file_path: str) -> bool
```

### Adding New Detectors

1. Create a new detector class inheriting from `BaseDetector`
2. Implement `scan_file()` method
3. Add to the `LumenaScanner.detectors` list

Example:
```python
class MyCustomDetector(BaseDetector):
    def __init__(self):
        super().__init__("My Detector")
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        # Your detection logic here
        return findings
```

## Exit Codes

- `0`: Success (no HIGH severity issues)
- `1`: Failure (HIGH severity issues found)

## Severity Levels

- **HIGH**: Critical security issues (secrets, dangerous functions)
- **MEDIUM**: Potential issues (AI drift signatures)
- **LOW**: Informational warnings
