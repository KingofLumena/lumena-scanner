"""
Tests for VaultDetector
"""

import os
import tempfile
import pytest
from lumena.detectors.vault_detector import VaultDetector


def test_vault_detector_initialization():
    """Test VaultDetector initialization."""
    detector = VaultDetector()
    assert detector is not None
    assert len(detector.findings) == 0


def test_detect_vault_token():
    """Test detection of Vault tokens."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('vault_token = "s.1234567890abcdefghij"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('vault' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_vault_addr():
    """Test detection of Vault addresses."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('VAULT_ADDR = "https://vault.example.com:8200"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('vault' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_root_token():
    """Test detection of root tokens."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
        f.write('ROOT_TOKEN="s.abcdefghij1234567890"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('root' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_vault_config_tls_disabled():
    """Test detection of disabled TLS in Vault config."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"disable_tls": true}\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('tls' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_dev_mode():
    """Test detection of development mode."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write('dev_mode: true\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('dev' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_recommendations():
    """Test that recommendations are provided."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('vault_token = "s.1234567890abcdefghij"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert all('recommendation' in f for f in findings)
    finally:
        os.unlink(temp_file)


def test_scan_directory():
    """Test directory scanning."""
    detector = VaultDetector()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        with open(os.path.join(tmpdir, 'config.py'), 'w') as f:
            f.write('VAULT_TOKEN = "s.1234567890abcdefghij"\n')
        
        with open(os.path.join(tmpdir, 'vault.json'), 'w') as f:
            f.write('{"disable_tls": true}\n')
        
        findings = detector.scan_directory(tmpdir)
        assert len(findings) > 0


def test_no_vault_issues():
    """Test file with no Vault issues."""
    detector = VaultDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# Regular code\n')
        f.write('def hello():\n')
        f.write('    print("Hello")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) == 0
    finally:
        os.unlink(temp_file)


def test_mask_value():
    """Test value masking."""
    detector = VaultDetector()
    
    masked = detector._mask_value("s.1234567890abcdefghij")
    assert masked.startswith("s.12")
    assert masked.endswith("ghij")
    assert "***" in masked
