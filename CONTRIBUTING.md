# Contributing to Lumena Scanner

Thank you for your interest in contributing to Lumena Scanner! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/lumena-scanner.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `pytest`
6. Commit your changes: `git commit -m "Description of changes"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/KingofLumena/lumena-scanner.git
cd lumena-scanner

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=lumena --cov-report=html
```

## Code Style

We follow standard Python conventions:

- **PEP 8** for code style
- **Type hints** for function signatures
- **Docstrings** for all public functions and classes
- **Black** for code formatting: `black lumena tests`
- **Flake8** for linting: `flake8 lumena tests`
- **MyPy** for type checking: `mypy lumena`

## Project Structure

```
lumena-scanner/
├── lumena/                 # Main package
│   ├── __init__.py
│   ├── cli.py             # CLI interface
│   ├── scanner.py         # Main scanner orchestrator
│   └── detectors/         # Detector modules
│       ├── __init__.py
│       ├── secret_detector.py
│       ├── ai_token_detector.py
│       ├── eval_detector.py
│       └── vault_detector.py
├── tests/                 # Test suite
│   ├── test_secret_detector.py
│   ├── test_ai_token_detector.py
│   ├── test_eval_detector.py
│   ├── test_vault_detector.py
│   └── test_scanner.py
├── pyproject.toml        # Project configuration
├── README.md             # Documentation
└── LICENSE               # MIT License
```

## Adding New Detectors

To add a new detector:

1. Create a new file in `lumena/detectors/` (e.g., `new_detector.py`)
2. Implement the detector class with these methods:
   - `__init__(self)`
   - `scan_file(self, file_path: str) -> List[Dict]`
   - `scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]`
   - `get_findings(self) -> List[Dict]`
   - `clear_findings(self)`

3. Add the detector to `lumena/detectors/__init__.py`
4. Integrate it in `lumena/scanner.py`
5. Add tests in `tests/test_new_detector.py`
6. Update documentation

Example detector structure:

```python
class NewDetector:
    """Detects [description]."""
    
    PATTERNS = {
        "pattern_name": re.compile(r'regex_pattern'),
    }
    
    def __init__(self):
        self.findings = []
    
    def scan_file(self, file_path: str) -> List[Dict]:
        findings = []
        # Implementation
        self.findings.extend(findings)
        return findings
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        # Implementation
        pass
    
    def get_findings(self) -> List[Dict]:
        return self.findings
    
    def clear_findings(self):
        self.findings = []
```

## Adding New Detection Patterns

To add a new pattern to an existing detector:

1. Add the pattern to the detector's pattern dictionary
2. Add a recommendation in the `_get_recommendation()` method
3. Add tests for the new pattern
4. Update documentation

## Testing

All new features should include tests:

```python
def test_new_feature():
    """Test description."""
    detector = YourDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('test_content')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('expected_type' in f.get('type', '') for f in findings)
    finally:
        os.unlink(temp_file)
```

Run tests frequently:

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_secret_detector.py

# Run specific test
pytest tests/test_secret_detector.py::test_detect_api_key

# Run with coverage
pytest --cov=lumena --cov-report=html

# View coverage report
open htmlcov/index.html  # On macOS
```

## Documentation

When adding new features:

1. Update the README.md with new detector capabilities
2. Add examples to EXAMPLES.md
3. Update CLI help text if needed
4. Add docstrings to all new functions and classes

## Commit Messages

Use clear, descriptive commit messages:

- ✅ "Add support for detecting Stripe API keys"
- ✅ "Fix false positive in JWT token detection"
- ✅ "Improve error handling in file scanner"
- ❌ "Fix bug"
- ❌ "Update code"

## Pull Request Guidelines

1. **Title**: Clear description of what the PR does
2. **Description**: Explain the changes and why they're needed
3. **Tests**: Include tests for new features
4. **Documentation**: Update relevant documentation
5. **Changes**: Keep PRs focused on a single feature/fix

## Code Review Process

1. All PRs require review before merging
2. Address review comments
3. Ensure all tests pass
4. Maintain code coverage above 80%

## Reporting Issues

When reporting issues:

1. Use the GitHub issue tracker
2. Include a clear description
3. Provide steps to reproduce
4. Include relevant code samples
5. Specify your environment (OS, Python version, etc.)

## Feature Requests

We welcome feature requests! Please:

1. Check if the feature already exists
2. Describe the use case
3. Explain the expected behavior
4. Provide examples if possible

## Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security concerns to the maintainers
3. Provide detailed information about the vulnerability
4. Allow time for the issue to be addressed before public disclosure

## License

By contributing to Lumena Scanner, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue for any questions about contributing!

---

**Thank you for contributing to Lumena Scanner!** 🔥
