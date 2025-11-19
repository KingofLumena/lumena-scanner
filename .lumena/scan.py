#!/usr/bin/env python3
"""
Lumena Scanner - AI Security Code Scanner
Scans repository for secrets, API keys, AI drift signatures, and dangerous function calls.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Any
from abc import ABC, abstractmethod


class Finding:
    """Represents a security finding."""
    
    def __init__(self, detector: str, severity: str, file_path: str, 
                 line_number: int, message: str, matched_text: str = ""):
        self.detector = detector
        self.severity = severity
        self.file_path = file_path
        self.line_number = line_number
        self.message = message
        self.matched_text = matched_text
    
    def __str__(self):
        return (f"⚠️  [{self.severity}] {self.detector} - {self.file_path}:{self.line_number}\n"
                f"   {self.message}")


class BaseDetector(ABC):
    """Base class for all security detectors."""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Scan file content and return list of findings."""
        pass
    
    def should_scan_file(self, file_path: str) -> bool:
        """Determine if this file should be scanned."""
        # Skip common binary and non-text files
        skip_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
            '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
            '.exe', '.dll', '.so', '.dylib',
            '.woff', '.woff2', '.ttf', '.eot',
            '.mp3', '.mp4', '.avi', '.mov', '.wav',
            '.pyc', '.class', '.o', '.a'
        }
        
        ext = Path(file_path).suffix.lower()
        if ext in skip_extensions:
            return False
        
        # Skip large files (> 1MB)
        try:
            if os.path.getsize(file_path) > 1_000_000:
                return False
        except OSError:
            return False
        
        return True


class VaultwatchDetector(BaseDetector):
    """Detects secrets, API keys, tokens, and credentials."""
    
    def __init__(self):
        super().__init__("Vaultwatch")
        
        # Pattern definitions for various secret types
        self.patterns = {
            'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'AWS Secret Key': re.compile(r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE),
            'GitHub Token': re.compile(r'gh[ps]_[a-zA-Z0-9]{36,}'),
            'GitHub PAT': re.compile(r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}'),
            'Generic API Key': re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE),
            'Generic Token': re.compile(r'(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.IGNORECASE),
            'Private Key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
            'Password in Code': re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
            'Slack Token': re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,}'),
            'Google API Key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            'Stripe API Key': re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
            'JWT Token': re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
            'Database Connection String': re.compile(r'(?:mongodb|mysql|postgres|postgresql)://[^:]+:[^@]+@', re.IGNORECASE),
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for secret_type, pattern in self.patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    # Skip if it looks like a placeholder or example
                    matched_text = match.group(0)
                    if self._is_false_positive(matched_text, line):
                        continue
                    
                    findings.append(Finding(
                        detector=self.name,
                        severity="HIGH",
                        file_path=file_path,
                        line_number=line_num,
                        message=f"Potential {secret_type} detected",
                        matched_text=matched_text
                    ))
        
        return findings
    
    def _is_false_positive(self, matched_text: str, line: str) -> bool:
        """Check if the match is likely a false positive."""
        false_positive_indicators = [
            'example', 'sample', 'dummy', 'placeholder', 'fake', 'test',
            'xxx', 'yyy', 'zzz', '***', '...', 'your_', 'your-',
            '<', '>', 'TODO', 'FIXME', 'INSERT', 'REPLACE'
        ]
        
        text_lower = matched_text.lower()
        line_lower = line.lower()
        
        return any(indicator in text_lower or indicator in line_lower 
                  for indicator in false_positive_indicators)


class FlameOverlayDetector(BaseDetector):
    """Detects AI drift signatures and anomalous AI-generated patterns."""
    
    def __init__(self):
        super().__init__("Flame Overlay")
        
        # Patterns that might indicate AI drift or suspicious AI behavior
        self.drift_patterns = {
            'Suspicious AI Comment': re.compile(r'(?:#|//|/\*)\s*(?:AI|GPT|Claude|ChatGPT|Copilot)\s+(?:generated|wrote|created|drift|anomaly)', re.IGNORECASE),
            'AI Instruction Leak': re.compile(r'(?:ignore previous|disregard|system prompt|instructions?:?\s*(?:you are|act as))', re.IGNORECASE),
            'Prompt Injection': re.compile(r'(?:execute|run|eval)\s*\(\s*(?:user[_-]?input|request|prompt)', re.IGNORECASE),
            'Model Override': re.compile(r'(?:override|bypass|disable)\s+(?:safety|security|filter|check)', re.IGNORECASE),
            'Suspicious Eval': re.compile(r'eval\s*\(\s*["\'].*(?:\$|`|\{)', re.IGNORECASE),
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            for drift_type, pattern in self.drift_patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append(Finding(
                        detector=self.name,
                        severity="MEDIUM",
                        file_path=file_path,
                        line_number=line_num,
                        message=f"Potential {drift_type} detected",
                        matched_text=match.group(0)
                    ))
        
        return findings


class EchoAnomalyDetector(BaseDetector):
    """Detects dangerous function calls and security vulnerabilities."""
    
    def __init__(self):
        super().__init__("Echo Anomaly")
        
        # Dangerous function patterns by language
        self.dangerous_patterns = {
            # Python
            'Python eval()': re.compile(r'\beval\s*\(', re.IGNORECASE),
            'Python exec()': re.compile(r'\bexec\s*\(', re.IGNORECASE),
            'Python pickle': re.compile(r'import\s+pickle|from\s+pickle\s+import|\bpickle\.loads?\s*\(', re.IGNORECASE),
            'Python __import__': re.compile(r'\b__import__\s*\('),
            'Python os.system': re.compile(r'\bos\.system\s*\('),
            'Python subprocess shell': re.compile(r'subprocess\.\w+\([^)]*shell\s*=\s*True', re.IGNORECASE),
            
            # JavaScript/TypeScript
            'JavaScript eval()': re.compile(r'\beval\s*\('),
            'JavaScript Function constructor': re.compile(r'new\s+Function\s*\('),
            'JavaScript innerHTML': re.compile(r'\.innerHTML\s*='),
            'JavaScript document.write': re.compile(r'\bdocument\.write\s*\('),
            
            # Shell/Bash
            'Shell Command Injection': re.compile(r'(?:bash|sh|zsh)\s+-c\s+["\']?\$'),
            
            # SQL
            'SQL Injection Risk': re.compile(r'(?:execute|query)\s*\([^)]*(?:\+|f["\']|\.format)', re.IGNORECASE),
            
            # General
            'Hardcoded localhost': re.compile(r'(?:http://localhost|127\.0\.0\.1):[0-9]+'),
            'Debug Mode Enabled': re.compile(r'(?:DEBUG|debug)\s*=\s*True', re.IGNORECASE),
            'Disabled Security': re.compile(r'(?:verify|ssl_verify|verify_ssl)\s*=\s*False', re.IGNORECASE),
        }
    
    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for danger_type, pattern in self.dangerous_patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append(Finding(
                        detector=self.name,
                        severity="HIGH",
                        file_path=file_path,
                        line_number=line_num,
                        message=f"Dangerous function detected: {danger_type}",
                        matched_text=match.group(0)
                    ))
        
        return findings


class LumenaScanner:
    """Main scanner orchestrator."""
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.detectors = [
            VaultwatchDetector(),
            FlameOverlayDetector(),
            EchoAnomalyDetector(),
        ]
        
        # Directories to skip
        self.skip_dirs = {
            '.git', 'node_modules', '__pycache__', '.pytest_cache',
            'venv', 'env', '.venv', '.env', 'dist', 'build', '.tox',
            '.eggs', '*.egg-info', 'target', 'bin', 'obj', 'out',
            '.idea', '.vscode', '.vs'
        }
        
        # Files to skip (scanner's own files and documentation)
        self.skip_files = {
            '.lumena/scan.py',  # Scanner's own code
            '.lumena/README.md',  # Scanner documentation
            'examples/vulnerable_code.md',  # Example vulnerable code
            'README.md',  # Main documentation
        }
    
    def scan(self) -> List[Finding]:
        """Scan all files in the repository."""
        all_findings = []
        
        print(f"🔍 Lumena Scanner starting...\n")
        print(f"Scanning: {self.root_path}\n")
        
        files_scanned = 0
        
        for file_path in self._get_files_to_scan():
            files_scanned += 1
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Get relative path for display
                rel_path = file_path.relative_to(self.root_path)
                rel_path_str = str(rel_path)
                
                # Skip files in the skip list
                if rel_path_str in self.skip_files:
                    continue
                
                for detector in self.detectors:
                    if detector.should_scan_file(str(file_path)):
                        findings = detector.scan_file(rel_path_str, content)
                        all_findings.extend(findings)
            
            except Exception as e:
                # Silently skip files that can't be read
                continue
        
        print(f"📊 Scanned {files_scanned} files\n")
        return all_findings
    
    def _get_files_to_scan(self):
        """Get all files that should be scanned."""
        for item in self.root_path.rglob('*'):
            if item.is_file():
                # Check if any parent directory should be skipped
                if any(skip_dir in item.parts for skip_dir in self.skip_dirs):
                    continue
                yield item
    
    def print_report(self, findings: List[Finding]):
        """Print scan results."""
        if not findings:
            print("✅ No security issues found!\n")
            return
        
        print(f"⚠️  Found {len(findings)} potential security issues:\n")
        print("=" * 80)
        
        # Group by severity
        high_findings = [f for f in findings if f.severity == "HIGH"]
        medium_findings = [f for f in findings if f.severity == "MEDIUM"]
        low_findings = [f for f in findings if f.severity == "LOW"]
        
        for severity, findings_list in [
            ("HIGH", high_findings),
            ("MEDIUM", medium_findings),
            ("LOW", low_findings)
        ]:
            if findings_list:
                print(f"\n🔴 {severity} Severity ({len(findings_list)} issues):")
                print("-" * 80)
                for finding in findings_list:
                    print(finding)
                    print()
        
        print("=" * 80)
        print(f"\n📌 Summary: {len(high_findings)} high, {len(medium_findings)} medium, {len(low_findings)} low\n")


def main():
    """Main entry point."""
    # Get repository root (parent of .lumena directory)
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    scanner = LumenaScanner(repo_root)
    findings = scanner.scan()
    scanner.print_report(findings)
    
    # Exit with error code if high severity issues found
    high_severity = [f for f in findings if f.severity == "HIGH"]
    if high_severity:
        print("❌ Scan completed with HIGH severity issues found.")
        sys.exit(1)
    else:
        print("✅ Scan completed successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
