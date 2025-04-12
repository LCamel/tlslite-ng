"""
TLS 1.3 Key Schedule Implementation - Client Handshake Traffic Secret and Application Traffic Secret.

This file calculates the client_handshake_traffic_secret and client_application_traffic_secret_0 
using the KeySchedule class from key_schedule4.py with the provided DH shared secret and handshake messages.
"""

import hashlib
from key_schedule import KeySchedule
from pathlib import Path

def read_bytes(filename):
    return Path("sample_data/server_openssl_client/saved_server/" + filename).read_bytes()

# Read required data from files
dh_shared_secret = read_bytes("003_dh_shared_secret")
client_hello = read_bytes("000_handshake_0")
server_hello = read_bytes("004_handshake_1")
encrypted_extensions = read_bytes("009_handshake_2")  # encrypted_extensions (8)
certificate = read_bytes("010_handshake_3")  # certificate (11)
certificate_verify = read_bytes("011_handshake_4")  # certificate_verify (15)
server_finished = read_bytes("012_handshake_5")  # finished (20) <== server Finished

# Initialize KeySchedule with SHA-256
key_schedule = KeySchedule(hashlib.sha256)

# Since we don't have a PSK, we're using the default all-zeros PSK
# (this happens automatically in KeySchedule.__init__)

# Set the DH shared secret to calculate handshake_secret and master_secret
key_schedule.set_DH_shared_secret(dh_shared_secret)

# Add handshake messages to the transcript
key_schedule.add_handshake(client_hello)
key_schedule.add_handshake(server_hello)

# Calculate handshake traffic secrets
client_hs_traffic, server_hs_traffic = key_schedule.calc_handshake_traffic_secrets()

# Print the client_handshake_traffic_secret in hex format
print("client_handshake_traffic_secret:", client_hs_traffic.hex())

# Add the remaining handshake messages to the transcript
key_schedule.add_handshake(encrypted_extensions)
key_schedule.add_handshake(certificate)
key_schedule.add_handshake(certificate_verify)
key_schedule.add_handshake(server_finished)

# Calculate application traffic secrets and other master-derived secrets
client_app_traffic, server_app_traffic, exporter_secret, resumption_secret = key_schedule.calc_master_derived_secrets()

# Print the client_application_traffic_secret_0 in hex format
print("client_application_traffic_secret_0:", client_app_traffic.hex())