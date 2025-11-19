"""
AI Token Detector - Detects AI service tokens (OpenAI, Anthropic, etc.)
"""

import re
from typing import List, Dict


class AITokenDetector:
    """Detects AI service API tokens and keys."""

    # Patterns for various AI service tokens
    AI_TOKEN_PATTERNS = {
        "openai_api_key": re.compile(
            r'sk-[a-zA-Z0-9]{20,}'
        ),
        "anthropic_api_key": re.compile(
            r'sk-ant-[a-zA-Z0-9\-]{20,}'
        ),
        "huggingface_token": re.compile(
            r'hf_[a-zA-Z0-9]{20,}'
        ),
        "google_ai_key": re.compile(
            r'AIza[0-9A-Za-z\-_]{35}'
        ),
        "cohere_api_key": re.compile(
            r'(?i)cohere[_-]?api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{40,})["\']'
        ),
        "azure_openai_key": re.compile(
            r'(?i)azure[_-]?openai[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9]{32})["\']'
        ),
        "replicate_api_token": re.compile(
            r'r8_[a-zA-Z0-9]{40,}'
        ),
        "stability_ai_key": re.compile(
            r'sk-[a-zA-Z0-9]{32,48}'
        ),
        "midjourney_token": re.compile(
            r'mj_[a-zA-Z0-9]{32,}'
        ),
        "openai_org_id": re.compile(
            r'org-[a-zA-Z0-9]{24,}'
        ),
    }

    def __init__(self):
        self.findings = []

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single file for AI tokens.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings with line numbers and detected tokens
        """
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, start=1):
                # Skip empty lines
                stripped = line.strip()
                if not stripped:
                    continue

                for token_type, pattern in self.AI_TOKEN_PATTERNS.items():
                    matches = pattern.finditer(line)
                    for match in matches:
                        matched_text = match.group(0)
                        if len(match.groups()) > 0:
                            token_value = match.group(1)
                        else:
                            token_value = matched_text

                        masked_token = self._mask_token(token_value)

                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "type": token_type,
                            "content": line.strip(),
                            "matched": masked_token,
                            "severity": "CRITICAL",
                            "category": "ai_token",
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
        Scan all files in a directory for AI tokens.

        Args:
            directory: Directory path to scan
            extensions: List of file extensions to scan

        Returns:
            List of all findings
        """
        import os

        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
                         '.yaml', '.yml', '.json', '.env', '.config', '.txt']

        findings = []
        for root, _, files in os.walk(directory):
            # Skip common directories
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__',
                                            '.venv', 'venv', 'dist', 'build']):
                continue

            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    findings.extend(self.scan_file(file_path))

        return findings

    def _mask_token(self, token: str) -> str:
        """Mask a token for safe display."""
        if len(token) <= 8:
            return "***"
        return token[:6] + "***" + token[-4:]

    def get_findings(self) -> List[Dict]:
        """Get all findings from scans."""
        return self.findings

    def clear_findings(self):
        """Clear all stored findings."""
        self.findings = []
