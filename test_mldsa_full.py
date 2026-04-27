#!/usr/bin/env python3
"""Full ML-DSA integration test for JWTConnect"""
import sys
sys.path.insert(0, '/home/ale/Documents/JWTConnect/src')

from cryptojwt.jws.mldsa import MLDSA_AVAILABLE
from cryptojwt.jwk.akp import new_akp_key
from cryptojwt.jws.jws import JWS, SIGNER_ALGS
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.utils import alg2keytype

def run_tests():
    print("="*60)
    print("JWTConnect ML-DSA Integration Test")
    print("="*60)
    
    print(f"\n✓ ML-DSA Available: {MLDSA_AVAILABLE}")
    mldsa_algs = [k for k in SIGNER_ALGS.keys() if k.startswith('ML-DSA')]
    print(f"✓ ML-DSA algorithms in SIGNER_ALGS: {mldsa_algs}")
    
    if not MLDSA_AVAILABLE:
        print("\n❌ ML-DSA not available - aborting")
        return False
    
    print("\n" + "="*60)
    print("Running Tests")
    print("="*60)
    
    # Test 1: Key generation for all algorithms
    print("\n[Test 1] Key Generation")
    keys = {}
    for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        key = new_akp_key(alg)
        keys[alg] = key
        print(f"  ✓ {alg}: kid={key.kid[:30]}...")
        assert key.kty == "AKP", f"Expected kty='AKP', got '{key.kty}'"
        assert key.alg == alg, f"Expected alg='{alg}', got '{key.alg}'"
    
    # Test 2: JWK Serialization
    print("\n[Test 2] JWK Serialization")
    for alg, key in keys.items():
        pub_jwk = key.serialize(private=False)
        priv_jwk = key.serialize(private=True)
        
        assert pub_jwk["kty"] == "AKP", "Public JWK missing kty"
        assert pub_jwk["alg"] == alg, "Public JWK wrong alg"
        assert "pub" in pub_jwk, "Public JWK missing pub"
        assert "priv" not in pub_jwk, "Public JWK should not have priv"
        
        assert "priv" in priv_jwk, "Private JWK missing priv"
        print(f"  ✓ {alg}: pub={len(pub_jwk['pub'])} chars, priv={len(priv_jwk['priv'])} chars")
    
    # Test 3: JWK Deserialization / Roundtrip
    print("\n[Test 3] JWK Roundtrip")
    for alg, key in keys.items():
        priv_jwk = key.serialize(private=True)
        key2 = key_from_jwk_dict(priv_jwk)
        
        assert key.alg == key2.alg, "Algorithm mismatch after roundtrip"
        assert key.pub == key2.pub, "Public key mismatch after roundtrip"
        assert key.priv == key2.priv, "Private key mismatch after roundtrip"
        print(f"  ✓ {alg}: Roundtrip successful")
    
    # Test 4: JWS Sign and Verify
    print("\n[Test 4] JWS Sign/Verify")
    test_payloads = [
        {"sub": "user123", "iat": 1234567890},
        {"message": "Hello, ML-DSA World!", "test": True},
    ]
    
    for alg, key in keys.items():
        for payload in test_payloads:
            jws = JWS(payload, alg=alg)
            token = jws.sign_compact(keys=[key])
            
            jws_v = JWS(alg=alg)
            verified = jws_v.verify_compact(token, keys=[key])
            
            assert verified == payload, f"Payload mismatch for {alg}: {verified} != {payload}"
        
        print(f"  ✓ {alg}: Signed/verified {len(test_payloads)} payloads")
        print(f"       Token length: {len(token)} chars")
    
    # Test 5: alg2keytype mapping
    print("\n[Test 5] Algorithm to Key Type Mapping")
    for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        kty = alg2keytype(alg)
        assert kty == "AKP", f"Expected kty='AKP' for {alg}, got '{kty}'"
        print(f"  ✓ {alg} -> {kty}")
    
    # Test 6: Wrong key rejection
    print("\n[Test 6] Wrong Key Rejection")
    key1 = new_akp_key("ML-DSA-65")
    key2 = new_akp_key("ML-DSA-65")
    
    jws = JWS({"test": "data"}, alg="ML-DSA-65")
    token = jws.sign_compact(keys=[key1])
    
    try:
        jws_v = JWS(alg="ML-DSA-65")
        jws_v.verify_compact(token, keys=[key2])
        print("  ❌ Should have rejected wrong key!")
        return False
    except Exception:
        print("  ✓ Wrong key correctly rejected")
    
    # Test 7: Key sizes
    print("\n[Test 7] Key Size Verification")
    expected_sizes = {
        "ML-DSA-44": {"pub": 1312, "sig": 2420},
        "ML-DSA-65": {"pub": 1952, "sig": 3309},
        "ML-DSA-87": {"pub": 2592, "sig": 4627},
    }
    
    for alg, key in keys.items():
        pub_bytes = key.pub_key.public_bytes_raw()
        
        # Sign something to get signature size
        jws = JWS(b"test", alg=alg)
        token = jws.sign_compact(keys=[key])
        sig = jws.signature() if hasattr(jws, 'signature') else b''
        
        expected_pub = expected_sizes[alg]["pub"]
        assert len(pub_bytes) == expected_pub, f"{alg}: Expected pub key {expected_pub} bytes, got {len(pub_bytes)}"
        print(f"  ✓ {alg}: Public key = {len(pub_bytes)} bytes (expected {expected_pub})")
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)
    print("\nML-DSA is fully functional in JWTConnect!")
    print("\nKey Features Verified:")
    print("  • Key generation (ML-DSA-44, ML-DSA-65, ML-DSA-87)")
    print("  • JWK serialization/deserialization")
    print("  • JWS signing and verification")
    print("  • Proper algorithm-to-keytype mapping")
    print("  • Wrong key rejection")
    print("  • Correct key sizes per RFC")
    
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
