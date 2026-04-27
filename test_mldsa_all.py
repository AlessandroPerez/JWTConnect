#!/usr/bin/env python3
"""
ML-DSA Test Suite Runner

Runs all ML-DSA related tests and provides comprehensive report.
"""

import sys
import subprocess
import time


def run_test(name, command):
    """Run a test and return (success, output)"""
    print(f"\n{'='*70}")
    print(f"Running: {name}")
    print('='*70)
    
    start = time.time()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        elapsed = time.time() - start
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        success = result.returncode == 0
        return success, elapsed
    except subprocess.TimeoutExpired:
        print(f"❌ TIMEOUT after 300 seconds")
        return False, 300
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False, 0


def main():
    print("="*70)
    print("JWTConnect ML-DSA Complete Test Suite")
    print("="*70)
    print("\nThis will run all ML-DSA tests:")
    print("  1. Module self-tests")
    print("  2. Integration tests")
    print("  3. RFC compliance tests")
    print("  4. Known Answer Tests (KAT)")
    print()
    
    tests = [
        ("ML-DSA Signer Module", "cd src && source .venv/bin/activate && python -m cryptojwt.jws.mldsa"),
        ("AKP Key Module", "cd src && source .venv/bin/activate && python -m cryptojwt.jwk.akp"),
        ("Integration Tests", "source src/.venv/bin/activate && python test_mldsa_full.py"),
        ("RFC Compliance Tests", "source src/.venv/bin/activate && python test_mldsa_compliance.py"),
        ("Known Answer Tests", "source src/.venv/bin/activate && python test_mldsa_kat.py"),
    ]
    
    results = []
    total_time = 0
    
    for name, command in tests:
        success, elapsed = run_test(name, command)
        results.append((name, success, elapsed))
        total_time += elapsed
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUITE SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for name, success, elapsed in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {name:<30} ({elapsed:.2f}s)")
    
    print("="*70)
    print(f"Total: {passed}/{total} test suites passed")
    print(f"Total time: {total_time:.2f}s")
    print("="*70)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! ML-DSA implementation is fully compliant.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test suite(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
