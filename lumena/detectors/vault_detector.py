"""
Vault Detector - Detects HashiCorp Vault configuration drifts and issues
"""

import re
import json
import yaml
from typing import List, Dict, Optional


class VaultDetector:
    """Detects HashiCorp Vault configuration issues and drifts."""

    # Patterns for Vault-related issues
    VAULT_PATTERNS = {
        "vault_token": re.compile(
            r'(?i)vault[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9\.\-_]{20,})["\']'
        ),
        "vault_addr": re.compile(
            r'(?i)vault[_-]?addr\s*[=:]\s*["\']?(https?://[^\s"\']+)["\']?'
        ),
        "vault_root_token": re.compile(
            r'(?i)root[_-]?token\s*[=:]\s*["\']([a-zA-Z0-9\.\-_]{20,})["\']'
        ),
        "hardcoded_vault_path": re.compile(
            r'(?i)vault\.read\s*\(["\']([^"\']+)["\']'
        ),
    }

    def __init__(self):
        self.findings = []

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single file for Vault configuration issues.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings with line numbers and detected issues
        """
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Pattern-based detection
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                for issue_type, pattern in self.VAULT_PATTERNS.items():
                    matches = pattern.finditer(line)
                    for match in matches:
                        matched_text = match.group(0)
                        if len(match.groups()) > 0:
                            value = match.group(1)
                        else:
                            value = matched_text

                        masked_value = self._mask_value(value)

                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "type": issue_type,
                            "content": line.strip(),
                            "matched": masked_value,
                            "severity": "HIGH",
                            "category": "vault_issue",
                            "recommendation": self._get_recommendation(issue_type),
                        })

            # Special handling for Vault configuration files
            if file_path.endswith(('.hcl', '.json', '.yaml', '.yml')):
                findings.extend(self._scan_vault_config(file_path, content))

        except Exception as e:
            findings.append({
                "file": file_path,
                "error": f"Failed to scan file: {str(e)}",
                "severity": "ERROR",
            })

        self.findings.extend(findings)
        return findings

    def _scan_vault_config(self, file_path: str, content: str) -> List[Dict]:
        """
        Scan Vault configuration files for specific issues.

        Args:
            file_path: Path to the configuration file
            content: File content

        Returns:
            List of findings
        """
        findings = []

        try:
            # Try to parse as JSON
            if file_path.endswith('.json'):
                config = json.loads(content)
                findings.extend(self._analyze_vault_config(file_path, config))
            
            # Try to parse as YAML
            elif file_path.endswith(('.yaml', '.yml')):
                config = yaml.safe_load(content)
                if config:
                    findings.extend(self._analyze_vault_config(file_path, config))

        except (json.JSONDecodeError, yaml.YAMLError):
            # If parsing fails, pattern matching already covered it
            pass
        except Exception:
            # Ignore parsing errors
            pass

        return findings

    def _analyze_vault_config(self, file_path: str, config: Dict) -> List[Dict]:
        """
        Analyze parsed Vault configuration for issues.

        Args:
            file_path: Path to the configuration file
            config: Parsed configuration

        Returns:
            List of findings
        """
        findings = []

        # Check for insecure Vault settings
        if isinstance(config, dict):
            # Check for disabled TLS
            if config.get('disable_tls') or config.get('tls_disable'):
                findings.append({
                    "file": file_path,
                    "type": "vault_tls_disabled",
                    "severity": "HIGH",
                    "category": "vault_drift",
                    "recommendation": "Enable TLS for Vault connections. Never disable TLS in production.",
                })

            # Check for insecure listener configuration
            listeners = config.get('listener', {})
            if isinstance(listeners, dict):
                for listener_type, listener_config in listeners.items():
                    if isinstance(listener_config, dict):
                        if listener_config.get('tls_disable'):
                            findings.append({
                                "file": file_path,
                                "type": "vault_listener_tls_disabled",
                                "severity": "HIGH",
                                "category": "vault_drift",
                                "recommendation": f"Enable TLS for {listener_type} listener.",
                            })

            # Check for development mode
            if config.get('dev_mode') or config.get('development'):
                findings.append({
                    "file": file_path,
                    "type": "vault_dev_mode",
                    "severity": "MEDIUM",
                    "category": "vault_drift",
                    "recommendation": "Development mode should not be used in production.",
                })

            # Check for insecure seal configuration
            seal = config.get('seal', {})
            if isinstance(seal, dict):
                if seal.get('type') == 'shamir' and config.get('storage', {}).get('type') == 'file':
                    findings.append({
                        "file": file_path,
                        "type": "vault_insecure_seal",
                        "severity": "MEDIUM",
                        "category": "vault_drift",
                        "recommendation": "Consider using auto-unseal with cloud KMS for better security.",
                    })

        return findings

    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        Scan all files in a directory for Vault issues.

        Args:
            directory: Directory path to scan
            extensions: List of file extensions to scan

        Returns:
            List of all findings
        """
        import os

        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
                         '.hcl', '.json', '.yaml', '.yml', '.env', '.config']

        findings = []
        for root, _, files in os.walk(directory):
            # Skip common directories
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__',
                                            '.venv', 'venv', 'dist', 'build']):
                continue

            for file in files:
                if any(file.endswith(ext) for ext in extensions) or 'vault' in file.lower():
                    file_path = os.path.join(root, file)
                    findings.extend(self.scan_file(file_path))

        return findings

    def _mask_value(self, value: str) -> str:
        """Mask a value for safe display."""
        if len(value) <= 8:
            return "***"
        return value[:4] + "***" + value[-4:]

    def _get_recommendation(self, issue_type: str) -> str:
        """Get security recommendation for the detected issue."""
        recommendations = {
            "vault_token": "Never hardcode Vault tokens. Use environment variables or secure token helpers.",
            "vault_addr": "Vault address should be configured via environment variables, not hardcoded.",
            "vault_root_token": "Never use or store root tokens in code. They should be securely managed.",
            "hardcoded_vault_path": "Avoid hardcoding Vault paths. Use configuration or environment variables.",
        }
        return recommendations.get(issue_type, "Review Vault configuration for security best practices.")

    def get_findings(self) -> List[Dict]:
        """Get all findings from scans."""
        return self.findings

    def clear_findings(self):
        """Clear all stored findings."""
        self.findings = []
