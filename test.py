#!/usr/bin/env python3

"""
Test script to calculate client_handshake_traffic_secret
based on the TLS 1.3 key schedule algorithm.

Inputs:
- DH shared secret from sample_data/server_openssl_client/saved_server/003_dh_shared_secret
- Client Hello transcript from sample_data/server_openssl_client/saved_server/000_handshake_0
- Server Hello transcript from sample_data/server_openssl_client/saved_server/004_handshake_1

We'll calculate the client_handshake_traffic_secret and compare with
sample_data/server_openssl_client/saved_server/008_client_handshake_traffic_secret
"""

from tlslite.utils.cryptomath import secureHMAC, derive_secret, HKDF_expand_label
from tlslite.handshakehashes import HandshakeHashes
import hashlib


def read_binary_file(file_path):
    """Read binary data from file."""
    try:
        with open(file_path, 'rb') as f:
            return bytearray(f.read())
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        return None


def calculate_client_handshake_traffic_secret():
    # Read the DH shared secret
    dh_shared_secret = read_binary_file("sample_data/server_openssl_client/saved_server/003_dh_shared_secret")
    if dh_shared_secret is None:
        return None

    # Read the handshake messages
    client_hello = read_binary_file("sample_data/server_openssl_client/saved_server/000_handshake_0")
    server_hello = read_binary_file("sample_data/server_openssl_client/saved_server/004_handshake_1")
    if client_hello is None or server_hello is None:
        return None

    # Set the hash algorithm to SHA-256 for TLS 1.3
    hash_algorithm = "sha256"
    digest_size = hashlib.sha256().digest_size  # 32 bytes for SHA256

    # Create HandshakeHashes object to calculate transcript hash
    handshake_hashes = HandshakeHashes()
    handshake_hashes.update(client_hello)
    handshake_hashes.update(server_hello)

    # TLS 1.3 Key Schedule:
    # 1. Initialize with empty secret (zeroed)
    secret = bytearray(digest_size)

    # 2. Early Secret calculation - No PSK in this case
    psk = bytearray(digest_size)  # No PSK, use a zeroed key
    early_secret = secureHMAC(secret, psk, hash_algorithm)
    print(f"Early Secret: {early_secret.hex()}")

    # 3. Derive 'derived' value from early secret
    derived_secret = derive_secret(early_secret, bytearray(b'derived'), None, hash_algorithm)
    print(f"Derived Secret: {derived_secret.hex()}")

    # 4. Handshake Secret calculation
    handshake_secret = secureHMAC(derived_secret, dh_shared_secret, hash_algorithm)
    print(f"Handshake Secret: {handshake_secret.hex()}")

    # 5. Client Handshake Traffic Secret
    client_handshake_traffic_secret = derive_secret(
        handshake_secret, 
        bytearray(b'c hs traffic'), 
        handshake_hashes, 
        hash_algorithm
    )
    print(f"Client Handshake Traffic Secret: {client_handshake_traffic_secret.hex()}")
    
    # Verify against saved value
    expected = read_binary_file("sample_data/server_openssl_client/saved_server/008_client_handshake_traffic_secret")
    if expected is not None:
        print(f"Expected: {expected.hex()}")
        if client_handshake_traffic_secret == expected:
            print("MATCH: Calculated secret matches the expected value!")
        else:
            print("ERROR: Calculated secret does not match the expected value!")
    
    return client_handshake_traffic_secret


if __name__ == "__main__":
    print("Starting TLS 1.3 key schedule calculation...")
    calculate_client_handshake_traffic_secret()