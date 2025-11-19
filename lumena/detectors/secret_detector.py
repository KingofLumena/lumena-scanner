"""
Secret Detector - Detects sensitive information like API keys, passwords, and tokens
"""

import re
from typing import List, Dict, Tuple


class SecretDetector:
    """Detects secrets and sensitive information in code."""

    # Comprehensive patterns for various secret types
    SECRET_PATTERNS = {
        "generic_api_key": re.compile(
            r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'
        ),
        "generic_secret": re.compile(
            r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'
        ),
        "aws_access_key": re.compile(
            r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?'
        ),
        "aws_secret_key": re.compile(
            r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']'
        ),
        "github_token": re.compile(
            r'(?i)github[_-]?token\s*[=:]\s*["\']?(ghp_[a-zA-Z0-9]{36})["\']?'
        ),
        "github_pat": re.compile(
            r'ghp_[a-zA-Z0-9]{30,}'
        ),
        "slack_token": re.compile(
            r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}'
        ),
        "slack_webhook": re.compile(
            r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
        ),
        "private_key": re.compile(
            r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----'
        ),
        "jwt_token": re.compile(
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        ),
        "generic_token": re.compile(
            r'(?i)token\s*[=:]\s*["\']([a-zA-Z0-9_\-]{32,})["\']'
        ),
        "connection_string": re.compile(
            r'(?i)(mongodb|mysql|postgresql|postgres)://[a-zA-Z0-9_]+:[^@\s]+@[^\s]+'
        ),
    }

    def __init__(self):
        self.findings = []

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single file for secrets.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings with line numbers and detected secrets
        """
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, start=1):
                # Skip comments and empty lines for some patterns
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue

                for secret_type, pattern in self.SECRET_PATTERNS.items():
                    matches = pattern.finditer(line)
                    for match in matches:
                        # Mask the secret for display
                        matched_text = match.group(0)
                        if len(match.groups()) > 0:
                            secret_value = match.group(len(match.groups()))
                        else:
                            secret_value = matched_text

                        masked_secret = self._mask_secret(secret_value)

                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "type": secret_type,
                            "content": line.strip(),
                            "matched": masked_secret,
                            "severity": "HIGH",
                        })

        except Exception as e:
            findings.append({
                "file": file_path,
                "error": f"Failed to scan file: {str(e)}",
                "severity": "ERROR",
            })

        self.findings.extend(findings)
        return findings

    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        Scan all files in a directory for secrets.

        Args:
            directory: Directory path to scan
            extensions: List of file extensions to scan (e.g., ['.py', '.js'])

        Returns:
            List of all findings
        """
        import os

        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php', 
                         '.yaml', '.yml', '.json', '.env', '.config', '.xml']

        findings = []
        for root, _, files in os.walk(directory):
            # Skip common directories that shouldn't be scanned
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 
                                            '.venv', 'venv', 'dist', 'build']):
                continue

            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    findings.extend(self.scan_file(file_path))

        return findings

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret for safe display."""
        if len(secret) <= 8:
            return "***"
        return secret[:4] + "***" + secret[-4:]

    def get_findings(self) -> List[Dict]:
        """Get all findings from scans."""
        return self.findings

    def clear_findings(self):
        """Clear all stored findings."""
        self.findings = []
