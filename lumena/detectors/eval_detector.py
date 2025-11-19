"""
Eval Detector - Detects dangerous eval() and exec() calls
"""

import re
import ast
from typing import List, Dict


class EvalDetector:
    """Detects potentially dangerous eval() and exec() calls in code."""

    # Patterns for dangerous code execution
    EVAL_PATTERNS = {
        "eval_call": re.compile(r'\beval\s*\('),
        "exec_call": re.compile(r'\bexec\s*\('),
        "compile_call": re.compile(r'\bcompile\s*\('),
        "subprocess_shell": re.compile(r'subprocess\.\w+\([^)]*shell\s*=\s*True'),
        "os_system": re.compile(r'\bos\.system\s*\('),
        "popen": re.compile(r'\bos\.popen\s*\('),
        "__import__": re.compile(r'\b__import__\s*\('),
        "pickle_loads": re.compile(r'\bpickle\.loads?\s*\('),
        "yaml_unsafe": re.compile(r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader'),
        "javascript_eval": re.compile(r'\beval\s*\('),
        "function_constructor": re.compile(r'new\s+Function\s*\('),
        "settimeout_string": re.compile(r'setTimeout\s*\(\s*["\']'),
        "setinterval_string": re.compile(r'setInterval\s*\(\s*["\']'),
    }

    def __init__(self):
        self.findings = []

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single file for dangerous eval/exec calls.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings with line numbers and detected calls
        """
        findings = []
        
        # Determine if this is a Python file for AST analysis
        is_python = file_path.endswith('.py')
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Pattern-based detection for all files
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                    continue

                for eval_type, pattern in self.EVAL_PATTERNS.items():
                    matches = pattern.finditer(line)
                    for match in matches:
                        findings.append({
                            "file": file_path,
                            "line": line_num,
                            "type": eval_type,
                            "content": line.strip(),
                            "severity": "HIGH",
                            "category": "dangerous_call",
                            "recommendation": self._get_recommendation(eval_type),
                        })

            # Additional AST-based analysis for Python files
            if is_python and content.strip():
                findings.extend(self._ast_scan(file_path, content))

        except Exception as e:
            findings.append({
                "file": file_path,
                "error": f"Failed to scan file: {str(e)}",
                "severity": "ERROR",
            })

        self.findings.extend(findings)
        return findings

    def _ast_scan(self, file_path: str, content: str) -> List[Dict]:
        """
        Use Python AST to detect eval/exec calls more accurately.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            List of findings
        """
        findings = []
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = None
                    
                    # Direct function calls like eval() or exec()
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    # Module function calls like os.system()
                    elif isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            module = node.func.value.id
                            attr = node.func.attr
                            func_name = f"{module}.{attr}"
                    
                    if func_name in ['eval', 'exec', 'compile', '__import__']:
                        findings.append({
                            "file": file_path,
                            "line": node.lineno,
                            "type": f"{func_name}_call_ast",
                            "severity": "HIGH",
                            "category": "dangerous_call",
                            "recommendation": f"Avoid using {func_name}(). Consider safer alternatives.",
                        })

        except SyntaxError:
            # If AST parsing fails, pattern matching already covered it
            pass
        except Exception:
            # Ignore AST errors, pattern matching is the fallback
            pass

        return findings

    def scan_directory(self, directory: str, extensions: List[str] = None) -> List[Dict]:
        """
        Scan all files in a directory for dangerous eval/exec calls.

        Args:
            directory: Directory path to scan
            extensions: List of file extensions to scan

        Returns:
            List of all findings
        """
        import os

        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.rb', '.php', '.pl']

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

    def _get_recommendation(self, eval_type: str) -> str:
        """Get security recommendation for the detected issue."""
        recommendations = {
            "eval_call": "Avoid using eval(). Use ast.literal_eval() for safe evaluation of literals.",
            "exec_call": "Avoid using exec(). Consider restructuring your code to avoid dynamic execution.",
            "compile_call": "Use compile() with caution. Ensure input is from trusted sources only.",
            "subprocess_shell": "Avoid shell=True. Use shell=False with a list of arguments.",
            "os_system": "Avoid os.system(). Use subprocess.run() with shell=False instead.",
            "popen": "Avoid os.popen(). Use subprocess.run() with proper argument handling.",
            "__import__": "Avoid __import__(). Use import statements or importlib.import_module().",
            "pickle_loads": "Use pickle with caution. Never unpickle data from untrusted sources.",
            "yaml_unsafe": "Use yaml.safe_load() instead of yaml.load() with unsafe loaders.",
            "javascript_eval": "Avoid eval() in JavaScript. Use JSON.parse() for JSON data.",
            "function_constructor": "Avoid Function constructor. It's similar to eval().",
            "settimeout_string": "Pass a function reference to setTimeout(), not a string.",
            "setinterval_string": "Pass a function reference to setInterval(), not a string.",
        }
        return recommendations.get(eval_type, "Review this code for security implications.")

    def get_findings(self) -> List[Dict]:
        """Get all findings from scans."""
        return self.findings

    def clear_findings(self):
        """Clear all stored findings."""
        self.findings = []
