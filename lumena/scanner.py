"""
Scanner - Main scanning orchestrator for Lumena
"""

from typing import List, Dict, Optional
from .detectors import SecretDetector, AITokenDetector, EvalDetector, VaultDetector


class Scanner:
    """Main scanner that orchestrates all detectors."""

    def __init__(self):
        self.secret_detector = SecretDetector()
        self.ai_token_detector = AITokenDetector()
        self.eval_detector = EvalDetector()
        self.vault_detector = VaultDetector()

    def scan_file(self, file_path: str, detectors: Optional[List[str]] = None) -> Dict:
        """
        Scan a single file with specified detectors.

        Args:
            file_path: Path to the file to scan
            detectors: List of detector names to use (None = all)

        Returns:
            Dictionary with findings from each detector
        """
        results = {
            "file": file_path,
            "findings": [],
        }

        if detectors is None or "secrets" in detectors:
            results["findings"].extend(self.secret_detector.scan_file(file_path))

        if detectors is None or "ai_tokens" in detectors:
            results["findings"].extend(self.ai_token_detector.scan_file(file_path))

        if detectors is None or "eval" in detectors:
            results["findings"].extend(self.eval_detector.scan_file(file_path))

        if detectors is None or "vault" in detectors:
            results["findings"].extend(self.vault_detector.scan_file(file_path))

        return results

    def scan_directory(
        self, 
        directory: str, 
        detectors: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None
    ) -> Dict:
        """
        Scan a directory with specified detectors.

        Args:
            directory: Path to the directory to scan
            detectors: List of detector names to use (None = all)
            extensions: File extensions to scan

        Returns:
            Dictionary with all findings
        """
        all_findings = []

        if detectors is None or "secrets" in detectors:
            all_findings.extend(
                self.secret_detector.scan_directory(directory, extensions)
            )

        if detectors is None or "ai_tokens" in detectors:
            all_findings.extend(
                self.ai_token_detector.scan_directory(directory, extensions)
            )

        if detectors is None or "eval" in detectors:
            all_findings.extend(
                self.eval_detector.scan_directory(directory, extensions)
            )

        if detectors is None or "vault" in detectors:
            all_findings.extend(
                self.vault_detector.scan_directory(directory, extensions)
            )

        return {
            "directory": directory,
            "total_findings": len(all_findings),
            "findings": all_findings,
        }

    def get_summary(self, findings: List[Dict]) -> Dict:
        """
        Generate a summary of findings.

        Args:
            findings: List of findings

        Returns:
            Summary dictionary
        """
        summary = {
            "total": len(findings),
            "by_severity": {},
            "by_type": {},
            "by_category": {},
        }

        for finding in findings:
            # Count by severity
            severity = finding.get("severity", "UNKNOWN")
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by type
            finding_type = finding.get("type", "unknown")
            summary["by_type"][finding_type] = summary["by_type"].get(finding_type, 0) + 1

            # Count by category
            category = finding.get("category", "other")
            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1

        return summary

    def clear_all_findings(self):
        """Clear findings from all detectors."""
        self.secret_detector.clear_findings()
        self.ai_token_detector.clear_findings()
        self.eval_detector.clear_findings()
        self.vault_detector.clear_findings()
