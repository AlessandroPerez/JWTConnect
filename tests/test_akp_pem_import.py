"""
Tests for AKP PEM/DER file import.
TDD: Write these tests before implementing file import support.
"""

import pytest
import tempfile
import os
from cryptography.hazmat.primitives import serialization

from cryptojwt.jwk.akp import (
    AKPKey,
    new_akp_key,
    MLDSA_AVAILABLE,
)


pytestmark = pytest.mark.skipif(not MLDSA_AVAILABLE, reason="ML-DSA not available")


class TestAKPPEMPrivateKeyImport:
    """Test importing private AKP keys from PEM files."""

    def test_import_private_key_from_pem_file(self, tmp_path):
        """Test importing private AKP key from PEM file."""
        # Generate a key
        key = new_akp_key("ML-DSA-65")
        
        # Serialize to PEM
        pem_data = key.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Write to temp file
        pem_file = tmp_path / "test_key.pem"
        pem_file.write_bytes(pem_data)
        
        # Import should work
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        imported_key = import_private_akp_key_from_file(str(pem_file))
        assert isinstance(imported_key, AKPKey)
        assert imported_key.alg == "ML-DSA-65"
        assert imported_key.has_private_key()

    def test_import_private_key_with_passphrase(self, tmp_path):
        """Test importing encrypted private key with passphrase."""
        key = new_akp_key("ML-DSA-65")
        
        # Serialize with encryption
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        pem_data = key.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"testpassword")
        )
        
        pem_file = tmp_path / "encrypted_key.pem"
        pem_file.write_bytes(pem_data)
        
        # Import with passphrase
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        imported_key = import_private_akp_key_from_file(str(pem_file), passphrase=b"testpassword")
        assert isinstance(imported_key, AKPKey)
        assert imported_key.has_private_key()

    def test_import_private_key_wrong_passphrase_fails(self, tmp_path):
        """Test that wrong passphrase raises error."""
        key = new_akp_key("ML-DSA-65")
        
        pem_data = key.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"correctpassword")
        )
        
        pem_file = tmp_path / "encrypted_key.pem"
        pem_file.write_bytes(pem_data)
        
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        with pytest.raises(Exception):
            import_private_akp_key_from_file(str(pem_file), passphrase=b"wrongpassword")


class TestAKPPEMPublicKeyImport:
    """Test importing public AKP keys from PEM files."""

    def test_import_public_key_from_pem_file(self, tmp_path):
        """Test importing public AKP key from PEM file."""
        key = new_akp_key("ML-DSA-65")
        
        # Serialize public key to PEM
        pem_data = key.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        pem_file = tmp_path / "test_pub.pem"
        pem_file.write_bytes(pem_data)
        
        from cryptojwt.jwk.akp import import_public_akp_key_from_file
        imported_key = import_public_akp_key_from_file(str(pem_file))
        assert isinstance(imported_key, AKPKey)
        assert imported_key.alg == "ML-DSA-65"
        assert not imported_key.has_private_key()

    def test_import_public_key_determines_algorithm(self, tmp_path):
        """Test that imported public key has correct algorithm."""
        for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            key = new_akp_key(alg)
            
            pem_data = key.pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            pem_file = tmp_path / f"test_{alg}.pem"
            pem_file.write_bytes(pem_data)
            
            from cryptojwt.jwk.akp import import_public_akp_key_from_file
            imported = import_public_akp_key_from_file(str(pem_file))
            assert imported.alg == alg


class TestAKPPEMDataImport:
    """Test importing from PEM data strings."""

    def test_import_from_pem_data_private(self):
        """Test importing private key from PEM data string."""
        key = new_akp_key("ML-DSA-65")
        pem_data = key.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        from cryptojwt.jwk.akp import import_akp_key_from_pem_data
        imported_key = import_akp_key_from_pem_data(pem_data)
        assert isinstance(imported_key, AKPKey)
        assert imported_key.has_private_key()

    def test_import_from_pem_data_public(self):
        """Test importing public key from PEM data string."""
        key = new_akp_key("ML-DSA-65")
        pem_data = key.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        from cryptojwt.jwk.akp import import_akp_key_from_pem_data
        imported_key = import_akp_key_from_pem_data(pem_data)
        assert isinstance(imported_key, AKPKey)
        assert not imported_key.has_private_key()


class TestAKPWrongKeyTypeRejection:
    """Test that importing wrong key types raises errors."""

    def test_import_rsa_key_as_akp_raises_error(self, tmp_path):
        """Test that importing RSA key as AKP raises error."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Create RSA key
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_data = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pem_file = tmp_path / "rsa_key.pem"
        pem_file.write_bytes(pem_data)
        
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        with pytest.raises(ValueError):
            import_private_akp_key_from_file(str(pem_file))

    def test_import_ec_key_as_akp_raises_error(self, tmp_path):
        """Test that importing EC key as AKP raises error."""
        from cryptography.hazmat.primitives.asymmetric import ec
        
        # Create EC key
        ec_key = ec.generate_private_key(ec.SECP256R1())
        pem_data = ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pem_file = tmp_path / "ec_key.pem"
        pem_file.write_bytes(pem_data)
        
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        with pytest.raises(ValueError):
            import_private_akp_key_from_file(str(pem_file))


class TestAKPKeyLoadMethod:
    """Test AKPKey.load() method for file loading."""

    def test_akp_key_load_private_from_file(self, tmp_path):
        """Test AKPKey.load() method with private key."""
        key = new_akp_key("ML-DSA-65")
        pem_data = key.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        pem_file = tmp_path / "test.pem"
        pem_file.write_bytes(pem_data)
        
        akp_key = AKPKey()
        loaded_key = akp_key.load(str(pem_file))
        
        assert isinstance(loaded_key, AKPKey)
        assert loaded_key.has_private_key()

    def test_akp_key_load_public_from_file(self, tmp_path):
        """Test AKPKey.load() method with public key."""
        key = new_akp_key("ML-DSA-65")
        pem_data = key.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        pem_file = tmp_path / "test.pem"
        pem_file.write_bytes(pem_data)
        
        akp_key = AKPKey()
        loaded_key = akp_key.load(str(pem_file))
        
        assert isinstance(loaded_key, AKPKey)
        assert not loaded_key.has_private_key()


class TestAKPFileErrors:
    """Test error handling for file operations."""

    def test_import_nonexistent_file_raises_error(self):
        """Test that importing from non-existent file raises error."""
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        with pytest.raises(FileNotFoundError):
            import_private_akp_key_from_file("/nonexistent/path.pem")

    def test_import_invalid_pem_raises_error(self, tmp_path):
        """Test that invalid PEM data raises error."""
        pem_file = tmp_path / "invalid.pem"
        pem_file.write_text("not a valid pem")
        
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        with pytest.raises(ValueError):
            import_private_akp_key_from_file(str(pem_file))

    def test_import_empty_file_raises_error(self, tmp_path):
        """Test that empty file raises error."""
        pem_file = tmp_path / "empty.pem"
        pem_file.write_text("")
        
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        with pytest.raises(ValueError):
            import_private_akp_key_from_file(str(pem_file))


class TestAKPDERFormat:
    """Test DER format import (if supported)."""

    def test_import_private_key_from_der_file(self, tmp_path):
        """Test importing private key from DER file."""
        key = new_akp_key("ML-DSA-65")
        
        # Serialize to DER
        der_data = key.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        der_file = tmp_path / "test_key.der"
        der_file.write_bytes(der_data)
        
        # Import should work (if DER support implemented)
        from cryptojwt.jwk.akp import import_private_akp_key_from_file
        try:
            imported_key = import_private_akp_key_from_file(str(der_file))
            assert isinstance(imported_key, AKPKey)
        except NotImplementedError:
            pytest.skip("DER format not yet supported")

    def test_import_public_key_from_der_file(self, tmp_path):
        """Test importing public key from DER file."""
        key = new_akp_key("ML-DSA-65")
        
        der_data = key.pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        der_file = tmp_path / "test_pub.der"
        der_file.write_bytes(der_data)
        
        from cryptojwt.jwk.akp import import_public_akp_key_from_file
        try:
            imported_key = import_public_akp_key_from_file(str(der_file))
            assert isinstance(imported_key, AKPKey)
        except NotImplementedError:
            pytest.skip("DER format not yet supported")
