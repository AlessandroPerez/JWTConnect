"""
Shared pytest fixtures for JWTConnect tests.
"""

import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from cryptojwt.jwk.akp import new_akp_key, MLDSA_AVAILABLE


@pytest.fixture
def skip_if_no_mldsa():
    """Skip test if ML-DSA not available."""
    if not MLDSA_AVAILABLE:
        pytest.skip("ML-DSA not available - cryptography not compiled with BoringSSL/AWS-LC")


@pytest.fixture
def akp_key_44():
    """Generate ML-DSA-44 key for tests."""
    if not MLDSA_AVAILABLE:
        pytest.skip("ML-DSA not available")
    return new_akp_key("ML-DSA-44")


@pytest.fixture
def akp_key_65():
    """Generate ML-DSA-65 key for tests."""
    if not MLDSA_AVAILABLE:
        pytest.skip("ML-DSA not available")
    return new_akp_key("ML-DSA-65")


@pytest.fixture
def akp_key_87():
    """Generate ML-DSA-87 key for tests."""
    if not MLDSA_AVAILABLE:
        pytest.skip("ML-DSA not available")
    return new_akp_key("ML-DSA-87")


@pytest.fixture
def akp_keys():
    """Generate all three ML-DSA key variants for tests."""
    if not MLDSA_AVAILABLE:
        pytest.skip("ML-DSA not available")
    return {
        "ML-DSA-44": new_akp_key("ML-DSA-44"),
        "ML-DSA-65": new_akp_key("ML-DSA-65"),
        "ML-DSA-87": new_akp_key("ML-DSA-87"),
    }
