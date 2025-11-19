# Extending Lumena Scanner

This guide shows how to add new security detectors to Lumena Scanner.

## Overview

Lumena Scanner uses a modular architecture where each detector is a class that inherits from `BaseDetector`. This makes it easy to add new detection capabilities without modifying the core scanner logic.

## Creating a New Detector

### Step 1: Define Your Detector Class

Create a new class that inherits from `BaseDetector`:

```python
from .scan import BaseDetector, Finding
import re

class MyCustomDetector(BaseDetector):
    def __init__(self):
        super().__init__("My Custom Detector")
        
        # Define your detection patterns
        self.patterns = {
            'Issue Type 1': re.compile(r'pattern1'),
            'Issue Type 2': re.compile(r'pattern2'),
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for issue_type, pattern in self.patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append(Finding(
                        detector=self.name,
                        severity="HIGH",  # or "MEDIUM" or "LOW"
                        file_path=file_path,
                        line_number=line_num,
                        message=f"Detected {issue_type}",
                        matched_text=match.group(0)
                    ))
        
        return findings
```

### Step 2: Register Your Detector

Add your detector to the scanner in `.lumena/scan.py`:

```python
class LumenaScanner:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.detectors = [
            VaultwatchDetector(),
            FlameOverlayDetector(),
            EchoAnomalyDetector(),
            MyCustomDetector(),  # Add your detector here
        ]
```

### Step 3: Test Your Detector

Create a test file with the pattern you're detecting and run the scanner:

```bash
python .lumena/scan.py
```

## Example: SQL Injection Detector

Here's a complete example of a detector for SQL injection vulnerabilities:

```python
class SQLInjectionDetector(BaseDetector):
    """Detects potential SQL injection vulnerabilities."""
    
    def __init__(self):
        super().__init__("SQL Shield")
        
        self.patterns = {
            'String Concatenation in SQL': re.compile(
                r'(?:execute|query|cursor\.execute)\s*\([^)]*(?:\+|f["\'])',
                re.IGNORECASE
            ),
            'Format String in SQL': re.compile(
                r'(?:execute|query)\s*\([^)]*\.format\s*\(',
                re.IGNORECASE
            ),
            'Percent Formatting in SQL': re.compile(
                r'(?:execute|query)\s*\([^)]*%\s*\(',
                re.IGNORECASE
            ),
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for vuln_type, pattern in self.patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append(Finding(
                        detector=self.name,
                        severity="HIGH",
                        file_path=file_path,
                        line_number=line_num,
                        message=f"Potential SQL injection: {vuln_type}",
                        matched_text=match.group(0)
                    ))
        
        return findings
```

## Best Practices

### 1. Choose Appropriate Severity Levels

- **HIGH**: Critical security issues (secrets, code injection, authentication bypass)
- **MEDIUM**: Potential issues that need review (suspicious patterns, deprecated APIs)
- **LOW**: Informational warnings (code style issues, minor security improvements)

### 2. Minimize False Positives

Add false positive checking:

```python
def _is_false_positive(self, matched_text: str, line: str) -> bool:
    """Check if match is likely a false positive."""
    false_positive_indicators = ['test', 'example', 'dummy']
    
    text_lower = matched_text.lower()
    line_lower = line.lower()
    
    return any(indicator in text_lower or indicator in line_lower 
              for indicator in false_positive_indicators)
```

### 3. Override `should_scan_file()` for File Type Filtering

If your detector only applies to specific file types:

```python
def should_scan_file(self, file_path: str) -> bool:
    """Only scan Python files."""
    return file_path.endswith('.py') and super().should_scan_file(file_path)
```

### 4. Use Descriptive Messages

Provide clear, actionable messages:

```python
message = f"Detected {issue_type} at line {line_num}. " \
          f"Consider using parameterized queries instead."
```

### 5. Document Your Patterns

Add comments explaining what each pattern detects:

```python
self.patterns = {
    # Detects direct string concatenation in SQL queries
    # Example: query = "SELECT * FROM users WHERE id=" + user_id
    'String Concatenation': re.compile(r'SELECT.*\+.*'),
}
```

## Testing Your Detector

Create a test file:

```python
# test_my_detector.py
def test_detector():
    detector = MyCustomDetector()
    
    # Test with vulnerable code
    vulnerable_code = """
    def bad_function():
        dangerous_pattern()
    """
    
    findings = detector.scan_file("test.py", vulnerable_code)
    
    assert len(findings) > 0, "Detector should find issues"
    assert findings[0].severity == "HIGH"
    print(f"✅ Detector found {len(findings)} issues")

if __name__ == "__main__":
    test_detector()
```

## Performance Considerations

1. **Use compiled regex patterns** (compile in `__init__`, not in `scan_file`)
2. **Skip unnecessary files** (override `should_scan_file()`)
3. **Avoid expensive operations** in the hot path
4. **Process line by line** rather than whole file when possible

## Contributing Your Detector

If you create a useful detector, consider contributing it back to the project!

1. Test thoroughly with various code samples
2. Document the detection patterns
3. Add example vulnerable code to `examples/`
4. Submit a pull request

## Examples of Future Detectors

Here are some ideas for additional detectors:

- **Crypto Weak**: Detects weak cryptographic algorithms (MD5, SHA1, DES)
- **Path Traversal**: Detects file path manipulation vulnerabilities
- **CORS Misconfiguration**: Detects overly permissive CORS settings
- **Hardcoded IPs**: Detects hardcoded IP addresses
- **TODO/FIXME Scanner**: Detects security-related TODO comments
- **Dependency Checker**: Detects known vulnerable dependencies

## Need Help?

Check the existing detectors in `.lumena/scan.py` for more examples:
- `VaultwatchDetector` - Secret detection
- `FlameOverlayDetector` - AI drift detection  
- `EchoAnomalyDetector` - Dangerous function detection
