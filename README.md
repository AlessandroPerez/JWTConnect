# cryptojwt

![License](https://img.shields.io/badge/license-Apache%202-blue.svg)
![Python version](https://img.shields.io/badge/python-3.10%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

An implementation of the JSON cryptographic specs JWS, JWE, JWK, and JWA [RFC 7515-7518] and JSON Web Token (JWT) [RFC 7519]

Please read the [Official Documentation](https://cryptojwt.readthedocs.io/en/latest/) for getting usage examples and further informations.

---

## ML-DSA (CRYSTALS-Dilithium) Support

This library now supports **ML-DSA** (Module Lattice-based Digital Signature Algorithm), a post-quantum cryptographic signature algorithm standardized in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and specified for use in JOSE/JWT contexts in [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/).

### Supported Algorithms

- `ML-DSA-44` - Public key: 1312 bytes, Signature: 2420 bytes
- `ML-DSA-65` - Public key: 1952 bytes, Signature: 3309 bytes
- `ML-DSA-87` - Public key: 2592 bytes, Signature: 4627 bytes

### Implementation Details

The ML-DSA implementation follows the [draft-ietf-cose-dilithium-11](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) specification with the following characteristics:

- **Key Type**: `AKP` (Algorithm Key Pair) as specified in the draft
- **Context**: Strictly uses empty bytes (`b""`) per RFC requirements
- **Private Key Format**: 32-byte seed format (not expanded)
- **Public Key Format**: Raw bytes encoded as base64url

### Implementation Changes

The following files were created or modified to add ML-DSA support:

#### New Files

1. **`src/cryptojwt/jws/mldsa.py`** - ML-DSA signer implementation
   - `MLDSASigner` class implementing sign/verify operations
   - Context (`ctx`) strictly set to empty bytes per RFC
   - Support for all three ML-DSA variants (44, 65, 87)
   - Maps algorithm names to cryptography library classes

2. **`src/cryptojwt/jwk/akp.py`** - AKP (Algorithm Key Pair) JWK implementation
   - `AKPKey` class for ML-DSA keys with `kty="AKP"`
   - Attributes: `alg` (required), `pub` (base64url), `priv` (base64url, optional)
   - `deserialize()` - Load from JWK dict using `from_seed_bytes()` / `from_public_bytes()`
   - `serialize(private=False)` - Export to JWK dict
   - `new_akp_key(alg, kid="")` - Key generation function

#### Modified Files

3. **`src/cryptojwt/jws/jws.py`** - Registered ML-DSA algorithms in `SIGNER_ALGS`
4. **`src/cryptojwt/jws/utils.py`** - Added `alg2keytype()` mapping: `ML-DSA-*` → `"AKP"`
5. **`src/cryptojwt/jwk/__init__.py`** - Added ML-DSA algorithms to validation lists
6. **`src/cryptojwt/jwk/jwk.py`** - Added AKP key type handling in `key_from_jwk_dict()`

### Requirements

ML-DSA requires `cryptography>=47.0.0` compiled with **BoringSSL** or **AWS-LC**. Standard PyPI wheels use OpenSSL, which does not support ML-DSA yet (support coming in OpenSSL 4.0).

### Setting Up the Environment

To use ML-DSA, you must build `cryptography` from source against AWS-LC or BoringSSL. Here's the complete setup:

#### Option 1: Build with AWS-LC (Recommended)

```bash
# 1. Clone and build AWS-LC
cd /tmp
git clone --depth 1 https://github.com/aws/aws-lc.git
cd aws-lc
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$HOME/.local/aws-lc
cmake --build build --parallel 4
cmake --install build --prefix $HOME/.local/aws-lc

# 2. Set up Python environment
cd /path/to/JWTConnect
uv venv src/.venv
source src/.venv/bin/activate

# 3. Build cryptography with AWS-LC
export OPENSSL_DIR=$HOME/.local/aws-lc
export OPENSSL_STATIC=1
export PATH="$HOME/.cargo/bin:$PATH"
export CFLAGS="-Wno-error=incompatible-pointer-types -Wno-error=deprecated-declarations"
uv pip install 'cryptography==47.0.0' --no-binary cryptography

# 4. Install remaining dependencies
uv pip install requests

# 5. Verify ML-DSA is available
python -c "from cryptography.hazmat.primitives.asymmetric import mldsa; \
           k = mldsa.MLDSA65PrivateKey.generate(); \
           print('✅ ML-DSA is working!')"
```

#### Option 2: Using Amazon Linux 2023 (Pre-built AWS-LC)

Amazon Linux 2023 includes AWS-LC by default:

```bash
# In Amazon Linux 2023 container
sudo yum install -y python3 python3-pip aws-lc-devel gcc rust cargo
pip install cryptography --no-binary cryptography
pip install requests
```

#### Option 3: Wait for OpenSSL 4.0

OpenSSL 4.0 will include ML-DSA support. Once released, standard PyPI wheels will work without custom builds.

### Usage Examples

#### Key Generation

```python
from cryptojwt.jwk.akp import new_akp_key

# Generate an ML-DSA-65 key
key = new_akp_key("ML-DSA-65", kid="my-key-id")

# Export public key as JWK
pub_jwk = key.serialize(private=False)
# Returns: {"kty": "AKP", "alg": "ML-DSA-65", "kid": "...", "pub": "..."}

# Export private key as JWK
priv_jwk = key.serialize(private=True)
# Returns: {"kty": "AKP", "alg": "ML-DSA-65", "kid": "...", "pub": "...", "priv": "..."}
```

#### Signing and Verifying JWTs

```python
from cryptojwt.jws.jws import JWS
from cryptojwt.jwk.akp import new_akp_key

# Generate a key
key = new_akp_key("ML-DSA-65")

# Create and sign a JWT
payload = {"sub": "user123", "iss": "example.com"}
jws = JWS(payload, alg="ML-DSA-65")
token = jws.sign_compact(keys=[key])

# Verify the JWT
jws_verify = JWS(alg="ML-DSA-65")
verified_payload = jws_verify.verify_compact(token, keys=[key])

print(verified_payload)  # {'sub': 'user123', 'iss': 'example.com'}
```

#### Loading Keys from JWK

```python
from cryptojwt.jwk.jwk import key_from_jwk_dict

# JWK dictionary
jwk_dict = {
    "kty": "AKP",
    "alg": "ML-DSA-65",
    "kid": "my-key",
    "pub": "base64url-encoded-public-key",
    "priv": "base64url-encoded-private-seed"  # optional
}

# Load the key
key = key_from_jwk_dict(jwk_dict)

# Use for signing or verification
```

### Testing

A comprehensive test suite ensures RFC compliance and security:

#### Test Files

1. **`test_mldsa_full.py`** - Integration tests covering:
   - Key generation for all algorithms
   - JWK serialization/deserialization
   - JWS signing and verification
   - Algorithm-to-keytype mapping
   - Wrong key rejection
   - Key size verification

2. **`test_mldsa_compliance.py`** - RFC compliance tests:
   - **FIPS 204 Compliance**: Key sizes, signature sizes, seed format
   - **draft-ietf-cose-dilithium-11**: AKP format, empty context, JWK structure
   - **RFC 7515/7517/7518**: JWS/JWK compliance
   - **Security**: Tampering detection, wrong algorithm rejection, signature randomness

3. **`test_mldsa_kat.py`** - Known Answer & Interoperability tests:
   - Deterministic key generation from seed
   - Signature structure validation
   - Context/message binding
   - Cross-algorithm isolation
   - Performance baseline

#### Running Tests

```bash
# Set up environment
source src/.venv/bin/activate

# Run integration tests
python test_mldsa_full.py

# Run RFC compliance tests
python test_mldsa_compliance.py

# Run KAT tests
python test_mldsa_kat.py

# Run all tests
python test_mldsa_all.py
```

Expected output:
```
============================================================
JWTConnect ML-DSA Integration Test
============================================================

✓ ML-DSA Available: True
✓ ML-DSA algorithms in SIGNER_ALGS: ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']

[Test 1] Key Generation
  ✓ ML-DSA-44: kid=...
  ✓ ML-DSA-65: kid=...
  ✓ ML-DSA-87: kid=...

[Test 2] JWK Serialization
  ✓ ML-DSA-44: pub=1750 chars, priv=43 chars
  ✓ ML-DSA-65: pub=2603 chars, priv=43 chars
  ✓ ML-DSA-87: pub=3456 chars, priv=43 chars

[Test 3] JWK Roundtrip
  ✓ ML-DSA-44: Roundtrip successful
  ✓ ML-DSA-65: Roundtrip successful
  ✓ ML-DSA-87: Roundtrip successful

[Test 4] JWS Sign/Verify
  ✓ ML-DSA-44: Signed/verified 2 payloads
  ✓ ML-DSA-65: Signed/verified 2 payloads
  ✓ ML-DSA-87: Signed/verified 2 payloads

[Test 5] Algorithm to Key Type Mapping
  ✓ ML-DSA-44 -> AKP
  ✓ ML-DSA-65 -> AKP
  ✓ ML-DSA-87 -> AKP

[Test 6] Wrong Key Rejection
  ✓ Wrong key correctly rejected

[Test 7] Key Size Verification
  ✓ ML-DSA-44: Public key = 1312 bytes (expected 1312)
  ✓ ML-DSA-65: Public key = 1952 bytes (expected 1952)
  ✓ ML-DSA-87: Public key = 2592 bytes (expected 2592)

============================================================
✅ ALL TESTS PASSED!
============================================================
```

### Troubleshooting

#### ML-DSA Not Available

If you see `ML-DSA not available`, your `cryptography` library is compiled with OpenSSL instead of AWS-LC/BoringSSL.

**Solution**: Follow the environment setup steps above to build cryptography with AWS-LC.

#### Build Errors

If building cryptography fails with AWS-LC:

1. Ensure you have the Rust toolchain installed: `cargo --version`
2. Install bindgen: `cargo install bindgen-cli`
3. Use the compiler flags to suppress warnings: `CFLAGS="-Wno-error=incompatible-pointer-types"`

#### Import Errors

If you get `ModuleNotFoundError: No module named 'cryptography'`:

```bash
# Ensure you're in the virtual environment
source src/.venv/bin/activate

# Verify cryptography is installed
python -c "import cryptography; print(cryptography.__version__)"
```

### References

- [FIPS 204 - Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) - Use of ML-DSA in JOSE and COSE
- [cryptography ML-DSA documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/)
- [AWS-LC Repository](https://github.com/aws/aws-lc)
- [BoringSSL Repository](https://boringssl.googlesource.com/boringssl/)
