# Lumena Scanner

Custom AI code scanner powered by Lumena's Flame Protocol — Driftprint, Vaultwatch, Token Shield.

## 🔍 What is Lumena Scanner?

Lumena Scanner is a Python-based security code scanner that automatically detects:
- **Secrets & API Keys** (AWS, GitHub, Stripe, etc.)
- **AI Drift Signatures** (prompt injections, AI instruction leaks)
- **Dangerous Function Calls** (eval, exec, unsafe operations)

It runs on every push and pull request via GitHub Actions, providing immediate feedback on security issues.

## 🚀 Quick Start

### Run Locally
```bash
python .lumena/scan.py
```

### Automatic Scanning
The scanner runs automatically on every push and pull request via GitHub Actions.

## 🏗️ Architecture

Lumena Scanner uses a modular detector architecture that makes it easy to add new security checks:

### Core Components

1. **BaseDetector** - Abstract base class for all detectors
2. **LumenaScanner** - Main orchestrator
3. **Finding** - Represents a security issue

### Built-in Detectors

#### 🔐 Vaultwatch (Secret Detection)
Detects leaked credentials:
- AWS Keys, GitHub Tokens, Stripe Keys
- Private Keys (RSA, EC, DSA)
- Database connection strings
- Generic API keys and tokens

#### 🔥 Flame Overlay (AI Drift Detection)
Identifies AI security risks:
- AI instruction leaks
- Prompt injection attempts
- Suspicious AI patterns

#### 🔊 Echo Anomaly (Dangerous Functions)
Detects unsafe code:
- Python: `eval()`, `exec()`, `pickle`, `os.system()`
- JavaScript: `eval()`, `innerHTML`, `document.write()`
- SQL injection risks
- Disabled security features

## 📊 Output

The scanner provides clear, actionable output:

```
🔍 Lumena Scanner starting...
📊 Scanned 42 files

⚠️  Found 3 potential security issues:

🔴 HIGH Severity (2 issues):
--------------------------------------------------------------------------------
⚠️  [HIGH] Vaultwatch - config.py:15
   Potential AWS Access Key detected

⚠️  [HIGH] Echo Anomaly - utils.py:23
   Dangerous function detected: Python eval()

🔴 MEDIUM Severity (1 issues):
--------------------------------------------------------------------------------
⚠️  [MEDIUM] Flame Overlay - prompt.py:8
   Potential AI Instruction Leak detected

📌 Summary: 2 high, 1 medium, 0 low
```

## 🔧 Extending the Scanner

Adding a new detector is simple:

```python
class MyDetector(BaseDetector):
    def __init__(self):
        super().__init__("My Detector")
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        # Add your detection logic here
        return findings
```

Then add it to the scanner in `.lumena/scan.py`:

```python
self.detectors = [
    VaultwatchDetector(),
    FlameOverlayDetector(),
    EchoAnomalyDetector(),
    MyDetector(),  # Add your detector
]
```

For a complete guide on creating custom detectors, see [EXTENDING.md](EXTENDING.md).

## 📋 Exit Codes

- `0` - Success (no HIGH severity issues)
- `1` - Failure (HIGH severity issues found)

## 🛠️ Configuration

The scanner automatically skips:
- Binary files (images, executables)
- Common dependency directories (`node_modules`, `venv`, etc.)
- Git directories (`.git`, `.github`)
- Large files (> 1MB)

## 📚 Learn More

For detailed documentation on each detector, see [`.lumena/README.md`](.lumena/README.md).

## 🤝 Contributing

Contributions are welcome! Feel free to add new detectors or improve existing ones.

## 📜 License

See [LICENSE](LICENSE) for details.
