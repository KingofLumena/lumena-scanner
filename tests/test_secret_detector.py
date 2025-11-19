"""
Tests for SecretDetector
"""

import os
import tempfile
import pytest
from lumena.detectors.secret_detector import SecretDetector


def test_secret_detector_initialization():
    """Test SecretDetector initialization."""
    detector = SecretDetector()
    assert detector is not None
    assert len(detector.findings) == 0


def test_detect_api_key():
    """Test detection of API keys."""
    detector = SecretDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('api' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_aws_access_key():
    """Test detection of AWS access keys."""
    detector = SecretDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('aws' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_github_token():
    """Test detection of GitHub tokens."""
    detector = SecretDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('github' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_private_key():
    """Test detection of private keys."""
    detector = SecretDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
        f.write('-----BEGIN RSA PRIVATE KEY-----\n')
        f.write('MIIEpAIBAAKCAQEA...\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('private_key' in f.get('type', '') for f in findings)
    finally:
        os.unlink(temp_file)


def test_mask_secret():
    """Test secret masking."""
    detector = SecretDetector()
    
    masked = detector._mask_secret("1234567890abcdefghij")
    assert masked.startswith("1234")
    assert masked.endswith("ghij")
    assert "***" in masked


def test_scan_directory():
    """Test directory scanning."""
    detector = SecretDetector()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        with open(os.path.join(tmpdir, 'test1.py'), 'w') as f:
            f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        
        with open(os.path.join(tmpdir, 'test2.js'), 'w') as f:
            f.write('const apiKey = "sk_test_abcdefghij1234567890";\n')
        
        findings = detector.scan_directory(tmpdir)
        assert len(findings) > 0


def test_no_secrets():
    """Test file with no secrets."""
    detector = SecretDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# This is a comment\n')
        f.write('print("Hello, World!")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) == 0
    finally:
        os.unlink(temp_file)


def test_clear_findings():
    """Test clearing findings."""
    detector = SecretDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('api_key = "sk_test_1234567890abcdefghij"\n')
        f.flush()
        temp_file = f.name
    
    try:
        detector.scan_file(temp_file)
        assert len(detector.get_findings()) > 0
        
        detector.clear_findings()
        assert len(detector.get_findings()) == 0
    finally:
        os.unlink(temp_file)
