"""
Tests for EvalDetector
"""

import os
import tempfile
import pytest
from lumena.detectors.eval_detector import EvalDetector


def test_eval_detector_initialization():
    """Test EvalDetector initialization."""
    detector = EvalDetector()
    assert detector is not None
    assert len(detector.findings) == 0


def test_detect_eval_call():
    """Test detection of eval() calls."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('result = eval("1 + 1")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('eval' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_exec_call():
    """Test detection of exec() calls."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('exec("print(\'Hello\')")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('exec' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_subprocess_shell():
    """Test detection of subprocess with shell=True."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import subprocess\n')
        f.write('subprocess.run("ls", shell=True)\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('subprocess' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_os_system():
    """Test detection of os.system() calls."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import os\n')
        f.write('os.system("echo hello")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('os_system' in f.get('type', '') for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_pickle_loads():
    """Test detection of pickle.loads() calls."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('import pickle\n')
        f.write('data = pickle.loads(user_input)\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('pickle' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_detect_javascript_eval():
    """Test detection of JavaScript eval()."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write('const result = eval("1 + 1");\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert any('eval' in f.get('type', '').lower() for f in findings)
    finally:
        os.unlink(temp_file)


def test_recommendations():
    """Test that recommendations are provided."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('result = eval("1 + 1")\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) > 0
        assert all('recommendation' in f for f in findings)
        assert all(len(f['recommendation']) > 0 for f in findings)
    finally:
        os.unlink(temp_file)


def test_scan_directory():
    """Test directory scanning."""
    detector = EvalDetector()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        with open(os.path.join(tmpdir, 'test1.py'), 'w') as f:
            f.write('result = eval("1 + 1")\n')
        
        with open(os.path.join(tmpdir, 'test2.js'), 'w') as f:
            f.write('eval("console.log(1)");\n')
        
        findings = detector.scan_directory(tmpdir)
        assert len(findings) > 0


def test_no_dangerous_calls():
    """Test file with no dangerous calls."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('def safe_function():\n')
        f.write('    return 1 + 1\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        assert len(findings) == 0
    finally:
        os.unlink(temp_file)


def test_ast_detection():
    """Test AST-based detection for Python files."""
    detector = EvalDetector()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('# Python file with eval\n')
        f.write('x = eval(user_input)\n')
        f.flush()
        temp_file = f.name
    
    try:
        findings = detector.scan_file(temp_file)
        # Should detect via both pattern and AST
        assert len(findings) > 0
    finally:
        os.unlink(temp_file)
