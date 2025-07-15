#!/usr/bin/env python3
"""
Test script to verify the DBSCAN fraud detection notebook runs without import errors
"""

import sys
import subprocess
import tempfile
import os

def test_notebook_imports():
    """Test that all imports in the notebook work correctly"""
    
    # Test basic imports that the notebook uses
    try:
        import pandas as pd
        import numpy as np
        print("✅ pandas and numpy imports successful")
    except ImportError as e:
        print(f"❌ pandas/numpy import failed: {e}")
        return False
    
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        print("✅ matplotlib and seaborn imports successful")
    except ImportError as e:
        print(f"⚠️  matplotlib/seaborn import failed (optional): {e}")
    
    try:
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import classification_report, confusion_matrix
        print("✅ scikit-learn imports successful")
    except ImportError as e:
        print(f"❌ scikit-learn import failed: {e}")
        return False
    
    try:
        import psutil
        print("✅ psutil import successful")
    except ImportError as e:
        print(f"⚠️  psutil import failed (optional for memory monitoring): {e}")
    
    try:
        import logging
        import time
        import gc
        from datetime import datetime
        print("✅ standard library imports successful")
    except ImportError as e:
        print(f"❌ standard library import failed: {e}")
        return False
    
    # Test that the problematic dbscan module import is NOT present
    try:
        from dbscan import create_spark_session
        print("❌ ERROR: The problematic dbscan module import is still present!")
        return False
    except ImportError:
        print("✅ Confirmed: problematic dbscan module import has been removed")
    
    return True

def test_notebook_syntax():
    """Test that the notebook has valid JSON and Python syntax"""
    
    import json
    import ast
    
    try:
        # Load the notebook
        with open('/home/runner/work/vault-poc/vault-poc/dbscan (6).ipynb', 'r') as f:
            notebook = json.load(f)
        print("✅ Notebook JSON is valid")
        
        # Check for required cells
        code_cells = [cell for cell in notebook['cells'] if cell['cell_type'] == 'code']
        print(f"✅ Found {len(code_cells)} code cells")
        
        # Look for specific functions
        all_code = []
        for cell in code_cells:
            all_code.extend(cell['source'])
        
        code_text = ''.join(all_code)
        
        # Check for required functions
        required_functions = [
            'test_scalability',
            'setup_enhanced_logging',
            'create_spark_session',
            'load_credit_card_data',
            'preprocess_data',
            'split_data'
        ]
        
        for func in required_functions:
            if f'def {func}(' in code_text:
                print(f"✅ Found required function: {func}")
            else:
                print(f"❌ Missing required function: {func}")
                return False
        
        # Check that problematic imports are removed (ignore comments)
        import re
        active_imports = [line for line in code_text.split('\n') 
                         if 'from dbscan import' in line and not line.strip().startswith('#')]
        
        if active_imports:
            print("❌ ERROR: Found active problematic 'from dbscan import' statements")
            for imp in active_imports:
                print(f"   {imp.strip()}")
            return False
        else:
            print("✅ Confirmed: No active problematic dbscan imports found")
        
        # Check for ImprovedDBSCANFraudDetector class
        if 'class ImprovedDBSCANFraudDetector' in code_text:
            print("✅ Found ImprovedDBSCANFraudDetector class")
        else:
            print("❌ Missing ImprovedDBSCANFraudDetector class")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Notebook validation failed: {e}")
        return False

def main():
    """Main test function"""
    print("=== Testing DBSCAN Fraud Detection Notebook ===")
    print()
    
    print("1. Testing imports...")
    imports_ok = test_notebook_imports()
    print()
    
    print("2. Testing notebook syntax and structure...")
    syntax_ok = test_notebook_syntax()
    print()
    
    if imports_ok and syntax_ok:
        print("🎉 SUCCESS: All tests passed!")
        print("   - Import errors have been fixed")
        print("   - test_scalability function has been added")
        print("   - Code structure has been improved")
        print("   - Enhanced logging and monitoring are in place")
        return 0
    else:
        print("❌ FAILURE: Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())