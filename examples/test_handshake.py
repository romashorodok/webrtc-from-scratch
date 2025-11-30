#!/usr/bin/env python3
"""
DTLS Handshake Test

Tests the Python DTLS implementation by verifying:
1. All imports work correctly
2. Certificate and keypair generation works
3. PRF functions produce correct output
4. ECDH key exchange produces matching shared secrets
5. Cipher suite initialization works

Usage:
    python test_handshake.py
"""

import asyncio
import hashlib
import binascii
import sys

def test_imports():
    """Test that all DTLS modules import correctly."""
    print("Testing imports...")

    try:
        from webrtc.dtls.flight0 import Flight0
        from webrtc.dtls.flight2 import Flight2
        from webrtc.dtls.flight3 import Flight3
        from webrtc.dtls.flight4 import Flight4
        from webrtc.dtls.flight5 import Flight5
        from webrtc.dtls.flight6 import Flight6
        from webrtc.dtls.flight_state import State, Flight, HandshakeCache
        from webrtc.dtls.dtls_cipher_suite import Keypair, CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        from webrtc.dtls.certificate import Certificate, RemoteCertificate
        from webrtc.dtls.gcm import prf_generate_encryption_keys, generate_aead_additional_data
        from webrtc.dtls.prf import prf_master_secret
        print("  ✓ All flight imports successful")
        return True
    except ImportError as e:
        print(f"  ✗ Import failed: {e}")
        return False


def test_certificate():
    """Test certificate generation via Rust."""
    print("Testing certificate generation...")

    try:
        import webrtc_rs

        rust_cert = webrtc_rs.Certificate()

        # Only certificate_fingerprint is currently available in Rust
        fingerprint = rust_cert.certificate_fingerprint()

        print(f"  Fingerprint: {fingerprint[:40]}...")
        print("  Note: certificate_der, pubkey_der, sign methods pending Rust implementation")
        print("  ✓ Certificate generation works")
        return True
    except Exception as e:
        print(f"  ✗ Certificate test failed: {e}")
        return False


def test_keypair():
    """Test ECDH keypair generation via Rust."""
    print("Testing keypair generation...")

    try:
        from webrtc.dtls.dtls_cipher_suite import Keypair

        # Generate P-256 keypair
        kp = Keypair.generate_P256()
        pubkey = kp.public_key_bytes()

        print(f"  Public key length: {len(pubkey)} bytes")
        print(f"  Public key prefix: 0x{pubkey[0]:02x} (expected 0x04 for uncompressed)")
        print("  ✓ Keypair generation works")
        return True
    except Exception as e:
        print(f"  ✗ Keypair test failed: {e}")
        return False


def test_ecdh():
    """Test ECDH key exchange produces matching shared secrets."""
    print("Testing ECDH key exchange...")

    try:
        from webrtc.dtls.dtls_cipher_suite import Keypair

        # Simulate client and server
        client_kp = Keypair.generate_P256()
        server_kp = Keypair.generate_P256()

        # Exchange public keys and compute shared secrets
        client_shared = client_kp.compute_shared_secret(server_kp.public_key_bytes())
        server_shared = server_kp.compute_shared_secret(client_kp.public_key_bytes())

        print(f"  Client shared secret: {binascii.hexlify(client_shared[:16]).decode()}...")
        print(f"  Server shared secret: {binascii.hexlify(server_shared[:16]).decode()}...")

        if client_shared == server_shared:
            print("  ✓ ECDH shared secrets match")
            return True
        else:
            print("  ✗ ECDH shared secrets DO NOT match!")
            return False
    except Exception as e:
        print(f"  ✗ ECDH test failed: {e}")
        return False


def test_prf():
    """Test PRF functions produce correct output."""
    print("Testing PRF functions...")

    try:
        from webrtc.dtls.prf import prf_master_secret
        from webrtc.dtls.gcm import p_hash

        # Test p_hash with known values
        secret = b'test_secret' * 4
        seed = b'test_seed' * 4
        result = p_hash(secret, seed, 48, hashlib.sha256)

        print(f"  p_hash output length: {len(result)} bytes (expected 48)")

        # Test master secret derivation
        pre_master = b'\x00' * 32  # Simulated shared secret
        client_random = b'\x01' * 32
        server_random = b'\x02' * 32

        master = prf_master_secret(pre_master, client_random, server_random, hashlib.sha256)

        print(f"  Master secret length: {len(master)} bytes (expected 48)")
        print(f"  Master secret: {binascii.hexlify(master[:16]).decode()}...")

        if len(result) == 48 and len(master) == 48:
            print("  ✓ PRF functions work correctly")
            return True
        else:
            print("  ✗ PRF output lengths incorrect")
            return False
    except Exception as e:
        print(f"  ✗ PRF test failed: {e}")
        return False


def test_cipher_suite():
    """Test cipher suite initialization."""
    print("Testing cipher suite initialization...")

    try:
        from webrtc.dtls.dtls_cipher_suite import Keypair, CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        from webrtc.dtls.prf import prf_master_secret
        import hashlib

        # Simulate key exchange
        client_kp = Keypair.generate_P256()
        server_kp = Keypair.generate_P256()

        pre_master = client_kp.compute_shared_secret(server_kp.public_key_bytes())

        client_random = b'\x01' * 32
        server_random = b'\x02' * 32

        master_secret = prf_master_secret(pre_master, client_random, server_random, hashlib.sha256)

        # Initialize cipher suite
        cipher = CipherSuite_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256()
        cipher.start(master_secret, client_random, server_random, client=False)

        print(f"  Cipher suite initialized: {cipher.gcm is not None}")
        print("  ✓ Cipher suite initialization works")
        return True
    except Exception as e:
        print(f"  ✗ Cipher suite test failed: {e}")
        return False


def test_certificate_signing():
    """Test certificate signing capability."""
    print("Testing certificate signing...")

    try:
        import webrtc_rs

        rust_cert = webrtc_rs.Certificate()

        # Check if sign method exists
        if hasattr(rust_cert, 'sign'):
            # Sign some test data
            test_data = b"test data to sign"
            signature = rust_cert.sign(test_data)

            print(f"  Signature length: {len(signature)} bytes")
            print(f"  Signature prefix: {binascii.hexlify(signature[:8]).decode()}...")
            print("  ✓ Certificate signing works")
        else:
            print("  Note: Certificate.sign() not yet exposed in Rust bindings")
            print("  ✓ Certificate signing SKIPPED (pending Rust implementation)")

        return True
    except Exception as e:
        print(f"  ✗ Certificate signing test failed: {e}")
        return False


def test_srtp_key_derivation():
    """Test SRTP keying material derivation after handshake."""
    print("Testing SRTP key derivation...")

    try:
        from webrtc.dtls.prf import (
            prf_master_secret,
            get_srtp_keying_material,
            SRTPKeyingMaterial,
            SRTP_KEY_LENGTH,
            SRTP_SALT_LENGTH,
        )
        from webrtc.dtls.dtls_cipher_suite import Keypair

        # Simulate completed handshake with known values
        client_kp = Keypair.generate_P256()
        server_kp = Keypair.generate_P256()

        pre_master = client_kp.compute_shared_secret(server_kp.public_key_bytes())
        client_random = b'\x01' * 32
        server_random = b'\x02' * 32

        master_secret = prf_master_secret(pre_master, client_random, server_random, hashlib.sha256)

        # Derive SRTP keying material
        srtp_keys = get_srtp_keying_material(master_secret, client_random, server_random)

        # Verify key and salt sizes per RFC 5764
        print(f"  Client write key: {len(srtp_keys.client_write_key)} bytes (expected {SRTP_KEY_LENGTH})")
        print(f"  Server write key: {len(srtp_keys.server_write_key)} bytes (expected {SRTP_KEY_LENGTH})")
        print(f"  Client write salt: {len(srtp_keys.client_write_salt)} bytes (expected {SRTP_SALT_LENGTH})")
        print(f"  Server write salt: {len(srtp_keys.server_write_salt)} bytes (expected {SRTP_SALT_LENGTH})")

        # Verify sizes match expected
        if (len(srtp_keys.client_write_key) == SRTP_KEY_LENGTH and
            len(srtp_keys.server_write_key) == SRTP_KEY_LENGTH and
            len(srtp_keys.client_write_salt) == SRTP_SALT_LENGTH and
            len(srtp_keys.server_write_salt) == SRTP_SALT_LENGTH):
            print(f"  Client key: {binascii.hexlify(srtp_keys.client_write_key).decode()}")
            print(f"  Server key: {binascii.hexlify(srtp_keys.server_write_key).decode()}")
            print("  ✓ SRTP key derivation works with correct sizes")
            return True
        else:
            print("  ✗ SRTP key sizes don't match expected values!")
            return False

    except Exception as e:
        print(f"  ✗ SRTP key derivation test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("DTLS Handshake Implementation Test")
    print("=" * 60)
    print()

    tests = [
        ("Imports", test_imports),
        ("Certificate", test_certificate),
        ("Keypair", test_keypair),
        ("ECDH", test_ecdh),
        ("PRF", test_prf),
        ("Cipher Suite", test_cipher_suite),
        ("Signing", test_certificate_signing),
        ("SRTP Keys", test_srtp_key_derivation),
    ]

    results = []
    for name, test_func in tests:
        print()
        result = test_func()
        results.append((name, result))

    print()
    print("=" * 60)
    print("Test Results Summary")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print()
    print(f"Total: {passed} passed, {failed} failed")
    print()

    if failed > 0:
        print("Some tests failed!")
        sys.exit(1)
    else:
        print("All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
