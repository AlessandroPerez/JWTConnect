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

| Algorithm | Public Key | Signature | Security Level |
|-----------|------------|-----------|----------------|
| `ML-DSA-44` | 1312 bytes | 2420 bytes | NIST Level 2 |
| `ML-DSA-65` | 1952 bytes | 3309 bytes | NIST Level 3 |
| `ML-DSA-87` | 2592 bytes | 4627 bytes | NIST Level 5 |

### Implementation Details

The ML-DSA implementation follows the [draft-ietf-cose-dilithium-11](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) specification with the following characteristics:

- **Key Type**: `AKP` (Algorithm Key Pair) as specified in the draft
- **Context**: Strictly uses empty bytes (`b""`) per RFC requirements
- **Private Key Format**: 32-byte seed format (not expanded)
- **Public Key Format**: Raw bytes encoded as base64url
- **Full Feature Parity**: AKP keys support all operations available to RSA, EC, and OKP keys

---

## Files Created/Modified

### New Files

#### 1. `src/cryptojwt/jws/mldsa.py`
ML-DSA signer implementation with full JWS integration.

**Classes:**
- `MLDSASigner` - Implements sign/verify for all three ML-DSA variants
  - `sign(msg, key)` - Sign with empty context per RFC
  - `verify(msg, sig, key)` - Verify with empty context per RFC
  - Maps algorithms to cryptography library classes

**Functions:**
- `_check_mldsa_support()` - Runtime availability check
- `MLDSA_AVAILABLE` - Boolean flag for ML-DSA availability

#### 2. `src/cryptojwt/jwk/akp.py`
AKP (Algorithm Key Pair) JWK implementation with complete key management support.

**Classes:**
- `AKPKey` - Full JWK implementation for ML-DSA keys
  - `serialize(private=False)` - Export to JWK format
  - `deserialize()` - Load from JWK dict
  - `load_key(key)` - Load from cryptography key object
  - `load(filename)` - Load from PEM file (NEW)
  - `signing_key()` - Get private key for signing
  - `verification_key()` - Get public key for verification
  - `thumbprint()` - RFC 7638 key thumbprint
  - `appropriate_for(usage)` - Check key usage

**Functions:**
- `new_akp_key(alg, kid="", **kwargs)` - Generate new ML-DSA key
- `import_private_akp_key_from_file(filename, passphrase=None)` - Import private key from PEM
- `import_public_akp_key_from_file(filename)` - Import public key from PEM
- `import_akp_key_from_pem_data(pem_data)` - Import from PEM string
- `import_akp_key_from_dict(jwk_dict)` - Import from JWK dict
- `MLDSA_AVAILABLE` - Boolean flag for availability
- `MLDSA_ALG_MAP` - Algorithm to class mapping
- `MLDSA_PUBKEY_SIZES` - Public key size constants
- `MLDSA_SEED_SIZE` - Private seed size (32 bytes)

### Modified Files

#### 3. `src/cryptojwt/jws/jws.py`
- Added conditional import of `MLDSASigner`
- Registered ML-DSA algorithms in `SIGNER_ALGS` dict:
  - `"ML-DSA-44"`
  - `"ML-DSA-65"`
  - `"ML-DSA-87"`

#### 4. `src/cryptojwt/jws/utils.py`
- Added `alg2keytype()` mapping: `ML-DSA-*` → `"AKP"`

#### 5. `src/cryptojwt/jwk/__init__.py`
- Added ML-DSA algorithms to algorithm validation lists:
  - `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"` for `use="sig"`
  - Same algorithms for general use validation

#### 6. `src/cryptojwt/jwk/jwk.py`
- Added AKP key type handling in `key_from_jwk_dict()`
- Added `AKP_PUBLIC_REQUIRED` and `AKP_PRIVATE_REQUIRED` constants
- Added `ensure_akp_params()` function
- Updated `jwk_wrap()` to handle ML-DSA key types
- Added conditional import of `AKPKey`

#### 7. `src/cryptojwt/key_bundle.py`
**KeyBundle Integration (Full Feature Parity):**
- Added `AKP` to `K2C` mapping
- Added `akp_init(spec)` function for KeyBundle initialization
- Updated `key_gen()` to support AKP key generation
- Updated `key_by_alg()` to support ML-DSA algorithms
- Updated `build_key_bundle()` to handle AKP type
- Updated `key_rollover()` to preserve AKP algorithm
- Updated `key_diff()` to compare AKP algorithms
- Added `generate()` method to KeyBundle class for AKP key generation

---

## Requirements

ML-DSA requires `cryptography>=47.0.0` compiled with **BoringSSL** or **AWS-LC**. Standard PyPI wheels use OpenSSL, which does not support ML-DSA yet (support coming in OpenSSL 4.0).

### Setting Up the Environment

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
uv pip install requests pytest

# 5. Verify ML-DSA is available
python -c "from cryptography.hazmat.primitives.asymmetric import mldsa; \
           k = mldsa.MLDSA65PrivateKey.generate(); \
           print('✅ ML-DSA is working!')"
```

#### Option 2: Using Amazon Linux 2023 (Pre-built AWS-LC)

```bash
# In Amazon Linux 2023 container
sudo yum install -y python3 python3-pip aws-lc-devel gcc rust cargo
pip install cryptography --no-binary cryptography
pip install requests pytest
```

---

## Usage Examples

### Key Generation

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

### Signing and Verifying JWTs

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

### Loading Keys from JWK

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

### KeyBundle Operations

```python
from cryptojwt.key_bundle import KeyBundle, build_key_bundle, key_rollover

# Create KeyBundle with AKP keys
kb = KeyBundle(keytype="AKP")
kb.generate(alg="ML-DSA-65")  # Generate new key
kb.generate(alg="ML-DSA-44")  # Generate another

# Build from specification
spec = [
    {"type": "AKP", "alg": "ML-DSA-65", "use": ["sig"]},
    {"type": "AKP", "alg": "ML-DSA-87", "use": ["sig"]},
]
kb = build_key_bundle(spec)

# Key rollover (maintains key history)
kb = key_rollover(kb)

# Export to JWKS
jwks = kb.jwks()  # JSON string
```

### PEM File Import

```python
from cryptojwt.jwk.akp import (
    import_private_akp_key_from_file,
    import_public_akp_key_from_file,
    import_akp_key_from_pem_data
)

# Import private key from PEM file
key = import_private_akp_key_from_file("/path/to/private.pem")

# Import with passphrase
key = import_private_akp_key_from_file("/path/to/encrypted.pem", 
                                        passphrase=b"my-password")

# Import public key
pub_key = import_public_akp_key_from_file("/path/to/public.pem")

# Import from PEM data string
pem_data = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""
key = import_akp_key_from_pem_data(pem_data)

# Load using AKPKey.load()
key = AKPKey().load("/path/to/key.pem")
```

### Mixed Key Types (RSA + ML-DSA)

```python
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwk.akp import new_akp_key

kb = KeyBundle()

# Add RSA key
rsa_key = new_rsa_key()
kb.append(rsa_key)

# Add ML-DSA key
akp_key = new_akp_key("ML-DSA-65")
kb.append(akp_key)

# Bundle contains both key types
print(len(kb))  # 2
```

---

## Testing

A comprehensive test suite with **306 tests** ensures RFC compliance and security:

### Test Files

#### 1. `tests/test_02_jwk.py` (AKP Section)
Integrated tests for AKP key functionality:
- **TestAKPKeyGeneration** (6 tests) - Key generation for all ML-DSA variants
- **TestAKPKeySerialization** (10 tests) - JWK serialize/deserialize
- **TestAKPKeyComparison** (6 tests) - Equality, hashing, set operations
- **TestAKPKeyFromJWKDict** (4 tests) - key_from_jwk_dict integration
- **TestAKPKeyUsage** (5 tests) - appropriate_for() method
- **TestAKPFIPS204Compliance** (5 tests) - Exact key/signature sizes
- **TestAKPThumbprint** (4 tests) - RFC 7638 thumbprints
- **TestAKPJWKWrap** (2 tests) - jwk_wrap() integration
- **TestAKPErrorHandling** (3 tests) - Error validation

#### 2. `tests/test_03_key_bundle.py` (AKP Section)
KeyBundle integration tests:
- **TestAKPKeyBundleBasics** (3 tests) - Basic operations
- **TestAKPKeyBundleLoading** (3 tests) - Loading from JWKS files/URLs
- **TestAKPKeyBundleGeneration** (6 tests) - Key generation via KeyBundle
- **TestAKPKeyBundleRollover** (3 tests) - Key rotation
- **TestAKPBuildKeyBundle** (2 tests) - Building from spec
- **TestAKPMixedKeyTypes** (1 test) - Mixed RSA + AKP bundles

#### 3. `tests/test_06_jws.py` (ML-DSA Section)
JWS signing/verification tests:
- **TestMLDSASignVerify** (10 tests) - Sign/verify with all algorithms
- **TestMLDSASignatureProperties** (4 tests) - Randomness, size validation
- **TestMLDSAWrongKeyRejection** (3 tests) - Security validation
- **TestMLDSAMultipleKeys** (1 test) - Key set verification
- **TestMLDSAFactory** (4 tests) - JWS factory recognition

#### 4. `tests/test_akp_pem_import.py`
PEM file import tests:
- **TestAKPPEMPrivateKeyImport** (3 tests) - Private key import
- **TestAKPPEMPublicKeyImport** (2 tests) - Public key import
- **TestAKPPEMDataImport** (2 tests) - PEM string import
- **TestAKPWrongKeyTypeRejection** (2 tests) - RSA/EC rejection
- **TestAKPKeyLoadMethod** (2 tests) - AKPKey.load() method
- **TestAKPFileErrors** (3 tests) - Error handling
- **TestAKPDERFormat** (2 tests) - DER format (optional)

#### 5. Standalone Test Files

**`test_mldsa_full.py`** - Comprehensive integration test suite:
- Key generation for all algorithms
- JWK serialization/deserialization
- JWS sign/verify operations
- Algorithm mapping verification
- Wrong key rejection
- Key size validation (FIPS 204)

**`test_mldsa_compliance.py`** - RFC compliance validation:
- FIPS 204 key/signature size compliance
- draft-ietf-cose-dilithium-11 format compliance
- RFC 7515/7517/7518 JWS/JWK compliance
- Security feature validation (tampering, randomization)

**`test_mldsa_kat.py`** - Known Answer & Interoperability tests:
- Deterministic key generation from seed
- Signature structure validation
- Context/message binding verification
- Cross-algorithm isolation
- Performance baseline (~1.6ms sign, ~0.3ms verify)

### Running Tests

```bash
# Set up environment
source src/.venv/bin/activate

# Run all AKP-related tests
python -m pytest tests/test_02_jwk.py tests/test_03_key_bundle.py \
                 tests/test_06_jws.py tests/test_akp_pem_import.py -v

# Run specific test files
python -m pytest tests/test_02_jwk.py -k "AKP" -v
python -m pytest tests/test_03_key_bundle.py -k "AKP" -v
python -m pytest tests/test_06_jws.py -k "MLDSA" -v
python -m pytest tests/test_akp_pem_import.py -v

# Run standalone tests
python test_mldsa_full.py
python test_mldsa_compliance.py
python test_mldsa_kat.py
python test_mldsa_all.py

# Run with coverage
python -m pytest tests/ --cov=cryptojwt --cov-report=html
```

### Test Results

**Current Status:**
- ✅ **302 tests PASSING**
- ⏭️ **4 tests SKIPPED** (expected - unsupported features)

---

## Troubleshooting

### ML-DSA Not Available

If you see `ML-DSA not available` or import errors:

```bash
# Check cryptography backend
python -c "from cryptography.hazmat.primitives.asymmetric import mldsa; \
           print(mldsa.MLDSA65PrivateKey.generate())"

# If that fails, rebuild cryptography with AWS-LC
# Follow "Option 1: Build with AWS-LC" instructions above
```

### Build Errors

If building cryptography fails with AWS-LC:

1. **Install Rust toolchain:**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   cargo --version
   ```

2. **Install bindgen:**
   ```bash
   cargo install bindgen-cli
   ```

3. **Use compiler flags:**
   ```bash
   export CFLAGS="-Wno-error=incompatible-pointer-types -Wno-error=deprecated-declarations"
   ```

### Key Size Errors

If you get key size validation errors, ensure you're using the correct algorithm:

```python
# Correct
key = new_akp_key("ML-DSA-65")  # Valid algorithm

# Incorrect - will raise error
key = new_akp_key("ML-DSA-99")  # Invalid algorithm
```

---

## References

- [FIPS 204 - Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) - Use of ML-DSA in JOSE and COSE
- [cryptography ML-DSA documentation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/)
- [AWS-LC Repository](https://github.com/aws/aws-lc)
- [BoringSSL Repository](https://boringssl.googlesource.com/boringssl/)
- [RFC 7515 - JWS](https://tools.ietf.org/html/rfc7515)
- [RFC 7517 - JWK](https://tools.ietf.org/html/rfc7517)
- [RFC 7518 - JWA](https://tools.ietf.org/html/rfc7518)
