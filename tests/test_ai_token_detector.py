"""
Tests for AITokenDetector
"""

import os
import tempfile
import pytest
from lumena.detectors.ai_token_detector import AITokenDetector


def test_ai_token_detector_initialization():
    """Test AITokenDetector initialization."""
    detector = AITokenDetector()
    assert detector is not None
    assert len(detector.findings) == 0


def test_detect_openai_key():
    """Test detection of OpenAI API keys."""
    detector = AITokenDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('openai_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789012"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('openai' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_anthropic_key():
    """Test detection of Anthropic API keys."""
    detector = AITokenDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('anthropic_key = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcd"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('anthropic' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_huggingface_token():
    """Test detection of HuggingFace tokens."""
    detector = AITokenDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('hf_token = "hf_abcdefghijklmnopqrstuvwxyz123456"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('huggingface' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_google_ai_key():
    """Test detection of Google AI keys."""
    detector = AITokenDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('google_key = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('google' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_mask_token():
    """Test token masking."""
    detector = AITokenDetector()
    
    masked = detector._mask_token("sk-1234567890abcdefghij")
    assert masked.startswith("sk-123")
    assert masked.endswith("ghij")
    assert "***" in masked


def test_scan_directory():
    """Test directory scanning."""
    detector = AITokenDetector()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        with open(os.path.join(tmpdir, 'config.py'), 'w') as f:
            f.write('OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789012"\n')
        
        with open(os.path.join(tmpdir, 'env.txt'), 'w') as f:
            f.write('HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz123456\n')
        
        findings = detector.scan_directory(tmpdir)
        assert len(findings) > 0


def test_no_ai_tokens():
    """Test file with no AI tokens."""
    detector = AITokenDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# Regular code\n')
        f.write('def hello():\n')
        f.write('    print("Hello, AI!")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) == 0
    finally:
        os.unlink(temp_file)


def test_severity_level():
    """Test that AI token findings have CRITICAL severity."""
    detector = AITokenDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('key = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789012"\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert all(f.get('severity') == 'CRITICAL' for f in findings)
    finally:
        os.unlink(temp_file)
