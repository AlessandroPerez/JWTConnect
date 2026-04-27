"""
AKP (Algorithm Key Pair) implementation for ML-DSA keys.

Implements the AKP key type as specified in draft-ietf-cose-dilithium.
AKP keys are used for algorithm-specific key pairs like ML-DSA.

Key format:
{
  "kty": "AKP",
  "alg": "ML-DSA-65",
  "pub": "<base64url-encoded public key>",
  "priv": "<base64url-encoded 32-byte seed>"  # optional
}
"""

from cryptography.hazmat.primitives import serialization

from ..exception import DeSerializationNotPossible, JWKESTException, UnsupportedAlgorithm
from ..utils import b64d, b64e
from .asym import AsymmetricKey

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

    # Public key sizes per algorithm
    MLDSA_PUBKEY_SIZES = {
        "ML-DSA-44": 1312,
        "ML-DSA-65": 1952,
        "ML-DSA-87": 2592,
    }

    # Private key (seed) size - always 32 bytes for ML-DSA
    MLDSA_SEED_SIZE = 32


def deser(val):
    """Deserialize base64url encoded value to bytes"""
    return b64d(val.encode()) if isinstance(val, str) else b64d(val)


class AKPKey(AsymmetricKey):
    """
    JSON Web key representation of an Algorithm Key Pair.
    
    According to draft-ietf-cose-dilithium, a JWK representation of an AKP key 
    can look like this::

        {
          "kty": "AKP",
          "alg": "ML-DSA-65",
          "pub": "<base64url-encoded public key>",
          "priv": "<base64url-encoded 32-byte seed>"
        }

    Parameters according to draft-ietf-cose-dilithium:
    - kty: MUST be "AKP"
    - alg: REQUIRED, one of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    - pub: Public key bytes (base64url encoded)
    - priv: Private key seed bytes, 32 bytes (base64url encoded), optional
    """

    members = AsymmetricKey.members[:]
    # The algorithm-specific attributes
    members.extend(["alg", "pub", "priv"])
    longs = ["pub", "priv"]
    public_members = AsymmetricKey.public_members[:]
    public_members.extend(["kty", "alg", "use", "kid", "pub"])
    # Required attributes
    required = ["kty", "alg", "pub"]

    def __init__(self, kty="AKP", alg="", use="", kid="", pub="", priv="", **kwargs):
        AsymmetricKey.__init__(self, kty, alg, use, kid, **kwargs)
        
        if kty != "AKP":
            raise ValueError(f'AKP key must have kty="AKP", got kty="{kty}"')
        
        self.alg = alg
        self.pub = pub
        self.priv = priv

        if not self.pub_key and not self.priv_key:
            if self.pub and self.alg:
                self.verify()
                self.deserialize()
            elif any([self.pub, self.alg]):
                raise JWKESTException("Missing required parameter")
        elif self.priv_key and not self.pub_key:
            self.pub_key = self.priv_key.public_key()
            self._serialize(self.priv_key)

    def _get_alg_classes(self):
        """Get the cryptography classes for this algorithm"""
        if not MLDSA_AVAILABLE:
            raise UnsupportedAlgorithm(
                "ML-DSA requires cryptography>=47.0.0 compiled with BoringSSL or AWS-LC"
            )
        if self.alg not in MLDSA_ALG_MAP:
            raise UnsupportedAlgorithm(f"Unknown AKP algorithm: {self.alg}")
        return MLDSA_ALG_MAP[self.alg]

    def deserialize(self):
        """
        Starting with information gathered from the on-the-wire representation
        of an AKP key (a JWK) initiate an ML-DSA key instance.
        
        If 'priv' has value then we're dealing with a private key otherwise
        a public key. 'pub' MUST have a value.
        """
        if not MLDSA_AVAILABLE:
            raise UnsupportedAlgorithm(
                "ML-DSA requires cryptography>=47.0.0 compiled with BoringSSL or AWS-LC"
            )

        priv_cls, pub_cls = self._get_alg_classes()
        expected_pubkey_size = MLDSA_PUBKEY_SIZES.get(self.alg)

        if isinstance(self.pub, (str, bytes)):
            _pub = deser(self.pub)
        else:
            raise ValueError('"pub" MUST be a string')

        # Validate public key size
        if expected_pubkey_size and len(_pub) != expected_pubkey_size:
            raise DeSerializationNotPossible(
                f"Invalid public key size for {self.alg}: expected {expected_pubkey_size}, got {len(_pub)}"
            )

        if self.priv:
            try:
                if isinstance(self.priv, (str, bytes)):
                    _priv = deser(self.priv)
                    # Validate seed size (always 32 bytes for ML-DSA)
                    if len(_priv) != MLDSA_SEED_SIZE:
                        raise DeSerializationNotPossible(
                            f"Invalid seed size: expected {MLDSA_SEED_SIZE}, got {len(_priv)}"
                        )
                    self.priv_key = priv_cls.from_seed_bytes(_priv)
                    self.pub_key = self.priv_key.public_key()
            except ValueError as exc:
                raise DeSerializationNotPossible(str(exc)) from exc
        else:
            try:
                self.pub_key = pub_cls.from_public_bytes(_pub)
            except ValueError as exc:
                raise DeSerializationNotPossible(str(exc)) from exc

    def _serialize_public(self, key):
        """Serialize public key to base64url string"""
        self.pub = b64e(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

    def _serialize_private(self, key):
        """Serialize private key (seed) to base64url string"""
        self._serialize_public(key.public_key())
        self.priv = b64e(
            key.private_bytes_raw()
        ).decode("ascii")

    def _serialize(self, key):
        """Serialize key based on its type"""
        if not MLDSA_AVAILABLE:
            raise UnsupportedAlgorithm(
                "ML-DSA requires cryptography>=47.0.0 compiled with BoringSSL or AWS-LC"
            )

        # Determine algorithm from key type
        for alg_name, (priv_cls, pub_cls) in MLDSA_ALG_MAP.items():
            if isinstance(key, priv_cls):
                self.alg = alg_name
                self._serialize_private(key)
                return
            elif isinstance(key, pub_cls):
                self.alg = alg_name
                self._serialize_public(key)
                return
        
        raise ValueError(f"Unknown AKP key type: {type(key)}")

    def serialize(self, private=False):
        """
        Go from an ML-DSA key instance to a JWK representation.

        :param private: Whether we should include the private attributes or not.
        :return: A JWK as a dictionary
        """
        if self.priv_key:
            self._serialize(self.priv_key)
        elif self.pub_key:
            self._serialize(self.pub_key)

        res = self.common()
        res.update({"pub": self.pub})

        if private and self.priv:
            res["priv"] = self.priv

        return res

    def load_key(self, key):
        """
        Load an AKP key

        :param key: An ML-DSA key instance, private or public.
        :return: Reference to this instance
        """
        self._serialize(key)

        if hasattr(key, 'private_bytes_raw'):
            self.priv_key = key
            self.pub_key = key.public_key()
        else:
            self.pub_key = key

        return self

    def signing_key(self):
        """
        Get a key appropriate for signing a message.

        :return: An ML-DSA private key instance
        """
        return self.priv_key

    def verification_key(self):
        """
        Get a key appropriate for verifying a signature.

        :return: An ML-DSA public key instance
        """
        return self.pub_key

    def __hash__(self) -> int:
        return super().__hash__()

    def __eq__(self, other):
        """
        Verify that the other key has the same properties as myself.

        :param other: The other key
        :return: True if the keys are the same otherwise False
        """
        if self.__class__ != other.__class__:
            return False

        if self.alg != other.alg:
            return False

        if not MLDSA_AVAILABLE:
            return False

        _, pub_cls = MLDSA_ALG_MAP.get(self.alg, (None, None))
        if not pub_cls:
            return False

        # Compare public keys
        if isinstance(self.pub_key, pub_cls) and isinstance(other.pub_key, pub_cls):
            if (self.pub_key.public_bytes_raw() != other.pub_key.public_bytes_raw()):
                return False
        else:
            return False

        # Compare private keys if both have them
        priv_cls, _ = MLDSA_ALG_MAP.get(self.alg, (None, None))
        if self.priv_key and other.priv_key:
            if isinstance(self.priv_key, priv_cls) and isinstance(other.priv_key, priv_cls):
                if (self.priv_key.private_bytes_raw() != other.priv_key.private_bytes_raw()):
                    return False
            else:
                return False
        elif self.priv_key or other.priv_key:
            # One has private key, the other doesn't
            return False

        return True

    def key_len(self):
        """Return key length"""
        if not MLDSA_AVAILABLE:
            raise UnsupportedAlgorithm(
                "ML-DSA requires cryptography>=47.0.0 compiled with BoringSSL or AWS-LC"
            )
        # Return signature size as "key length"
        return MLDSA_PUBKEY_SIZES.get(self.alg, 0)


def new_akp_key(alg: str, kid: str = "", **kwargs) -> "AKPKey":
    """
    Generate a new AKP key for the specified algorithm.

    :param alg: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    :param kid: Optional key ID
    :param kwargs: Additional key attributes
    :return: An AKPKey instance
    """
    if not MLDSA_AVAILABLE:
        raise UnsupportedAlgorithm(
            "ML-DSA requires cryptography>=47.0.0 compiled with BoringSSL or AWS-LC"
        )

    if alg not in MLDSA_ALG_MAP:
        raise UnsupportedAlgorithm(f"Unknown AKP algorithm: {alg}")

    priv_cls, _ = MLDSA_ALG_MAP[alg]
    _key = priv_cls.generate()

    _rk = AKPKey(priv_key=_key, alg=alg, kid=kid, **kwargs)
    if not kid:
        _rk.add_kid()

    return _rk


def import_akp_key_from_dict(jwk_dict: dict) -> "AKPKey":
    """
    Import an AKP key from a JWK dictionary.

    :param jwk_dict: Dictionary containing AKP key parameters
    :return: An AKPKey instance
    """
    return AKPKey(**jwk_dict)


if __name__ == "__main__":
    # Simple tests
    if not MLDSA_AVAILABLE:
        print("ML-DSA not available - skipping tests")
    else:
        print("Testing AKP/ML-DSA implementation...")

        for alg_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            print(f"\nTesting {alg_name}...")

            # Generate a key
            key = new_akp_key(alg_name)
            print(f"  Generated key with kid: {key.kid}")

            # Test serialization
            pub_jwk = key.serialize(private=False)
            print(f"  Public JWK keys: {list(pub_jwk.keys())}")
            assert "pub" in pub_jwk
            assert "priv" not in pub_jwk

            priv_jwk = key.serialize(private=True)
            print(f"  Private JWK keys: {list(priv_jwk.keys())}")
            assert "pub" in priv_jwk
            assert "priv" in priv_jwk

            # Test deserialization
            key2 = import_akp_key_from_dict(priv_jwk)
            assert key2.alg == alg_name
            assert key2.pub == key.pub
            assert key2.priv == key.priv
            print("  Deserialize/serialize roundtrip: OK")

            # Test key loading
            key3 = AKPKey().load_key(key.priv_key)
            assert key3.alg == alg_name
            print("  Key loading: OK")

            # Test thumbprint
            thumb = key.thumbprint("SHA-256")
            print(f"  Thumbprint: {thumb[:20]}...")

            # Test equality
            assert key == key2
            print("  Key equality: OK")

        print("\nAll tests passed!")
