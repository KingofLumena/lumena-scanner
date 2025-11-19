"""
Tests for Scanner
"""

import os
import tempfile
import pytest
from lumena.scanner import Scanner


def test_scanner_initialization():
    """Test Scanner initialization."""
    scanner = Scanner()
    assert scanner is not None
    assert scanner.secret_detector is not None
    assert scanner.ai_token_detector is not None
    assert scanner.eval_detector is not None
    assert scanner.vault_detector is not None


def test_scan_file():
    """Test scanning a single file."""
    scanner = Scanner()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        f.write('result = eval("1 + 1")\n')
        f.flush()
        temp_file = f.name
    
    try:
        results = scanner.scan_file(temp_file)
        assert 'file' in results
        assert 'findings' in results
        assert len(results['findings']) > 0
    finally:
        os.unlink(temp_file)


def test_scan_file_with_specific_detectors():
    """Test scanning with specific detectors."""
    scanner = Scanner()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        f.write('result = eval("1 + 1")\n')
        f.flush()
        temp_file = f.name
    
    try:
        # Only scan for secrets
        results = scanner.scan_file(temp_file, detectors=['secrets'])
        findings = results['findings']
        
        # Should find secrets but not eval calls
        assert len(findings) > 0
        assert all('api' in f.get('type', '').lower() or 'secret' in f.get('type', '').lower() 
                   for f in findings)
    finally:
        os.unlink(temp_file)


def test_scan_directory():
    """Test scanning a directory."""
    scanner = Scanner()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        with open(os.path.join(tmpdir, 'test1.py'), 'w') as f:
            f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        
        with open(os.path.join(tmpdir, 'test2.py'), 'w') as f:
            f.write('result = eval("1 + 1")\n')
        
        with open(os.path.join(tmpdir, 'test3.js'), 'w') as f:
            f.write('const key = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789012";\n')
        
        results = scanner.scan_directory(tmpdir)
        
        assert 'directory' in results
        assert 'total_findings' in results
        assert 'findings' in results
        assert results['total_findings'] > 0
        assert len(results['findings']) > 0


def test_get_summary():
    """Test getting summary of findings."""
    scanner = Scanner()
    
    findings = [
        {"severity": "HIGH", "type": "api_key", "category": "secret"},
        {"severity": "HIGH", "type": "eval_call", "category": "dangerous_call"},
        {"severity": "CRITICAL", "type": "openai_api_key", "category": "ai_token"},
        {"severity": "MEDIUM", "type": "vault_dev_mode", "category": "vault_drift"},
    ]
    
    summary = scanner.get_summary(findings)
    
    assert summary['total'] == 4
    assert 'by_severity' in summary
    assert 'by_type' in summary
    assert 'by_category' in summary
    
    assert summary['by_severity']['HIGH'] == 2
    assert summary['by_severity']['CRITICAL'] == 1
    assert summary['by_severity']['MEDIUM'] == 1


def test_clear_all_findings():
    """Test clearing all findings."""
    scanner = Scanner()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        f.flush()
        temp_file = f.name
    
    try:
        scanner.scan_file(temp_file)
        
        # Check that findings exist
        assert len(scanner.secret_detector.get_findings()) > 0
        
        # Clear all findings
        scanner.clear_all_findings()
        
        # Check that all findings are cleared
        assert len(scanner.secret_detector.get_findings()) == 0
        assert len(scanner.ai_token_detector.get_findings()) == 0
        assert len(scanner.eval_detector.get_findings()) == 0
        assert len(scanner.vault_detector.get_findings()) == 0
    finally:
        os.unlink(temp_file)


def test_multiple_detector_types():
    """Test scanning file with multiple types of issues."""
    scanner = Scanner()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# Multiple security issues\n')
        f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        f.write('openai_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789012"\n')
        f.write('result = eval(user_input)\n')
        f.write('vault_token = "s.abcdefghij1234567890"\n')
        f.flush()
        temp_file = f.name
    
    try:
        results = scanner.scan_file(temp_file)
        findings = results['findings']
        
        # Should find multiple types of issues
        assert len(findings) >= 4
        
        # Check for different categories
        categories = set(f.get('category', 'other') for f in findings)
        assert len(categories) > 1
    finally:
        os.unlink(temp_file)
