"""
ML-DSA (CRYSTALS-Dilithium) signature implementation.

Implements ML-DSA-44, ML-DSA-65, and ML-DSA-87 signature algorithms
as specified in draft-ietf-cose-dilithium.

Context (ctx) MUST be empty bytes per the RFC.
"""

from cryptography.exceptions import InvalidSignature

from ..exception import UnsupportedAlgorithm
from . import Signer

# Check if ML-DSA is available
def _check_mldsa_support():
    """Check if ML-DSA is available (cryptography>=47.0.0 with BoringSSL/AWS-LC)"""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        # Try to generate a test key to verify backend support
        mldsa.MLDSA44PrivateKey.generate()
        return True
    except (ImportError, Exception):
        return False


MLDSA_AVAILABLE = _check_mldsa_support()

if MLDSA_AVAILABLE:
    from cryptography.hazmat.primitives.asymmetric import mldsa

    # Algorithm name to cryptography class mapping
    MLDSA_ALG_MAP = {
        "ML-DSA-44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
        "ML-DSA-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
        "ML-DSA-87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
    }


class MLDSASigner(Signer):
    """
    Implements ML-DSA signature algorithm as specified in draft-ietf-cose-dilithium.

    Context (ctx) MUST be empty bytes per the RFC.

    NOTE: ML-DSA requires cryptography>=47.0.0 compiled with BoringSSL or AWS-LC.
    Standard PyPI wheels use OpenSSL which does not support ML-DSA yet.
    To use ML-DSA today, you must either:
    1. Build cryptography from source against BoringSSL/AWS-LC
    2. Use a container/image with pre-built support
    3. Wait for OpenSSL 4.0 (which will include ML-DSA support)
    """

    def __init__(self, algorithm: str):
        """
        Initialize ML-DSA signer.

        :param algorithm: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
        """
        if not MLDSA_AVAILABLE:
            raise UnsupportedAlgorithm(
                "ML-DSA is not available. This requires cryptography>=47.0.0 "
                "compiled with BoringSSL or AWS-LC (not OpenSSL).\n\n"
                "Standard PyPI wheels use OpenSSL, which doesn't support ML-DSA yet.\n\n"
                "To use ML-DSA, you can:\n"
                "1. Build cryptography from source against AWS-LC/BoringSSL\n"
                "2. Use a container with pre-built support (e.g., Amazon Linux 2023)\n"
                "3. Wait for OpenSSL 4.0 (coming soon with ML-DSA support)\n\n"
                "See: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/"
            )

        if algorithm not in MLDSA_ALG_MAP:
            raise UnsupportedAlgorithm(f"Unknown ML-DSA algorithm: {algorithm}")

        self.algorithm = algorithm
        self._priv_cls, self._pub_cls = MLDSA_ALG_MAP[algorithm]

    def sign(self, msg: bytes, key) -> bytes:
        """
        Sign a message using ML-DSA.

        Context (ctx) MUST be empty bytes per RFC.

        :param msg: The message to sign
        :param key: ML-DSA private key instance from cryptography library
        :return: The signature bytes
        """
        if not isinstance(key, (self._priv_cls,)):
            raise ValueError(
                f"Key must be an instance of {self._priv_cls.__name__}, got {type(key)}"
            )

        # Per RFC, context MUST be empty bytes (not None)
        return key.sign(msg, context=b"")

    def verify(self, msg: bytes, sig: bytes, key) -> bool:
        """
        Verify a signature using ML-DSA.

        Context (ctx) MUST be empty bytes per RFC.

        :param msg: The message that was signed
        :param sig: The signature to verify
        :param key: ML-DSA public key instance from cryptography library
        :return: True if signature is valid, False otherwise
        """
        if not isinstance(key, (self._pub_cls,)):
            raise ValueError(
                f"Key must be an instance of {self._pub_cls.__name__}, got {type(key)}"
            )

        try:
            # Per RFC, context MUST be empty bytes (not None)
            key.verify(sig, msg, context=b"")
            return True
        except InvalidSignature:
            return False


if __name__ == "__main__":
    # Simple tests
    if not MLDSA_AVAILABLE:
        print("ML-DSA not available - skipping tests")
    else:
        print("Testing ML-DSA implementation...")

        for alg_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            print(f"\nTesting {alg_name}...")

            signer = MLDSASigner(alg_name)

            # Generate a key
            priv_cls, pub_cls = MLDSA_ALG_MAP[alg_name]
            private_key = priv_cls.generate()
            public_key = private_key.public_key()

            # Test sign and verify
            message = b"test message"
            signature = signer.sign(message, private_key)
            print(f"  Signature length: {len(signature)} bytes")

            # Verify
            assert signer.verify(message, signature, public_key) is True
            print("  Sign + Verify: OK")

            # Verify with wrong message should fail
            assert signer.verify(b"wrong message", signature, public_key) is False
            print("  Wrong message rejection: OK")

            # Generate different key and verify should fail
            wrong_key = priv_cls.generate().public_key()
            assert signer.verify(message, signature, wrong_key) is False
            print("  Wrong key rejection: OK")

        print("\nAll tests passed!")
