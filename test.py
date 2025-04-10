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

Additionally, we'll calculate client_application_traffic_secret_0 using the
full transcript including encrypted_extensions, certificate, certificate_verify, 
server finished, and client finished messages.
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
    
    return client_handshake_traffic_secret, handshake_secret


def calculate_client_application_traffic_secret():
    # First calculate handshake traffic secret to get the handshake secret
    result = calculate_client_handshake_traffic_secret()
    if result is None:
        return None
    
    client_handshake_traffic_secret, handshake_secret = result
    
    # Read additional handshake messages for full transcript
    encrypted_extensions = read_binary_file("sample_data/server_openssl_client/saved_server/009_handshake_2")
    certificate = read_binary_file("sample_data/server_openssl_client/saved_server/010_handshake_3")
    certificate_verify = read_binary_file("sample_data/server_openssl_client/saved_server/011_handshake_4")
    server_finished = read_binary_file("sample_data/server_openssl_client/saved_server/012_handshake_5")
    client_finished = read_binary_file("sample_data/server_openssl_client/saved_server/016_handshake_6")
    
    if None in (encrypted_extensions, certificate, certificate_verify, server_finished, client_finished):
        print("Error: Missing required handshake message files")
        return None
    
    # Read the master secret directly
    expected_master_secret = read_binary_file("sample_data/server_openssl_client/saved_server/013_master_secret")
    print(f"Expected Master Secret: {expected_master_secret.hex()}")
    
    # Read expected application secret
    expected = read_binary_file("sample_data/server_openssl_client/saved_server/014_client_application_traffic_secret_0")
    print(f"Expected Application Secret: {expected.hex()}")
    
    # Set the hash algorithm to SHA-256 for TLS 1.3
    hash_algorithm = "sha256"
    digest_size = hashlib.sha256().digest_size
    
    # Try a completely new approach - using directly the contents of the existing files without any intermediate processing
    
    # For TLS 1.3, calculate master secret from handshake secret
    # Master Secret = HKDF-Extract(Derived Secret, 0)
    derived_secret = derive_secret(handshake_secret, bytearray(b'derived'), None, hash_algorithm)
    calculated_master_secret = secureHMAC(derived_secret, bytearray(0), hash_algorithm)
    print(f"Calculated Master Secret: {calculated_master_secret.hex()}")
    
    # Check if our master secret calculation matches the expected one
    if calculated_master_secret == expected_master_secret:
        print("MATCH: Calculated master secret matches the expected value!")
    else:
        print("ERROR: Calculated master secret does not match the expected value!")
    
    # Create fresh HandshakeHashes to calculate the transcript hash
    handshake_hashes_full = HandshakeHashes()
    
    # Add the handshake messages from the sample data
    client_hello = read_binary_file("sample_data/server_openssl_client/saved_server/000_handshake_0")
    server_hello = read_binary_file("sample_data/server_openssl_client/saved_server/004_handshake_1")
    
    # Add messages in order
    print("Adding handshake messages to transcript hash:")
    print(f"Client Hello ({len(client_hello)} bytes)")
    handshake_hashes_full.update(client_hello)
    
    print(f"Server Hello ({len(server_hello)} bytes)")
    handshake_hashes_full.update(server_hello)
    
    print(f"Encrypted Extensions ({len(encrypted_extensions)} bytes)")
    handshake_hashes_full.update(encrypted_extensions)
    
    print(f"Certificate ({len(certificate)} bytes)")
    handshake_hashes_full.update(certificate)
    
    print(f"Certificate Verify ({len(certificate_verify)} bytes)")
    handshake_hashes_full.update(certificate_verify)
    
    print(f"Server Finished ({len(server_finished)} bytes)")
    handshake_hashes_full.update(server_finished)
    
    print(f"Client Finished ({len(client_finished)} bytes)")
    handshake_hashes_full.update(client_finished)
    
    transcript_hash = handshake_hashes_full.digest(hash_algorithm)
    print(f"Full Handshake Hash: {transcript_hash.hex()}")
    
    # Use expected master secret for client application traffic secret calculation
    client_app_traffic_secret = derive_secret(
        expected_master_secret,
        bytearray(b'c ap traffic'),
        handshake_hashes_full,
        hash_algorithm
    )
    
    print(f"Client Application Traffic Secret (using expected master secret): {client_app_traffic_secret.hex()}")
    
    # Debugging: Try to brute-force approach - check if the expected application secret can be derived
    # with any handshake message combinations
    print("\nTrying other combinations of handshake messages for transcript hash:")
    
    # Try client_hello through server_finished only (exclude client_finished)
    handshake_hashes_server_finished = HandshakeHashes()
    handshake_hashes_server_finished.update(client_hello)
    handshake_hashes_server_finished.update(server_hello)
    handshake_hashes_server_finished.update(encrypted_extensions)
    handshake_hashes_server_finished.update(certificate)
    handshake_hashes_server_finished.update(certificate_verify)
    handshake_hashes_server_finished.update(server_finished)
    
    hash_server_finished = handshake_hashes_server_finished.digest(hash_algorithm)
    print(f"Hash up to Server Finished: {hash_server_finished.hex()}")
    
    # Try with this hash value
    app_secret_server_finished = derive_secret(
        expected_master_secret,
        bytearray(b'c ap traffic'),
        handshake_hashes_server_finished,
        hash_algorithm
    )
    print(f"App Secret with Server Finished: {app_secret_server_finished.hex()}")
    if app_secret_server_finished == expected:
        print("MATCH found with server_finished (excluding client_finished)!")
        
    # Check what was actually used to derive the expected application traffic secret
    if app_secret_server_finished == expected:
        print("\nSolution found! The transcript hash for the client_application_traffic_secret_0")
        print("includes handshake messages up to server_finished but excludes client_finished.")
    else:
        print("\nNo matching transcript hash found for the expected client_application_traffic_secret_0.")
    
    return client_app_traffic_secret


if __name__ == "__main__":
    print("Starting TLS 1.3 key schedule calculation...")
    print("\n=== Calculating Client Handshake Traffic Secret ===")
    calculate_client_handshake_traffic_secret()
    
    print("\n=== Calculating Client Application Traffic Secret ===")
    calculate_client_application_traffic_secret()