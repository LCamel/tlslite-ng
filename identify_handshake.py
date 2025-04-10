#!/usr/bin/env python3
# Save as identify_handshake.py

import sys

# Handshake types as per TLS 1.3
HANDSHAKE_TYPES = {
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    5: "end_of_early_data",
    8: "encrypted_extensions",
    11: "certificate",
    13: "certificate_request",
    15: "certificate_verify",
    20: "finished",
    24: "key_update",
    254: "message_hash"
}

def identify_handshake_file(filename):
    try:
        with open(filename, 'rb') as f:
            first_byte = f.read(1)
            if not first_byte:
                return f"Error: {filename} is empty"
            
            byte_value = ord(first_byte)
            if byte_value in HANDSHAKE_TYPES:
                return f"{filename}: {HANDSHAKE_TYPES[byte_value]} ({byte_value})"
            else:
                return f"{filename}: Unknown handshake type ({byte_value})"
    except Exception as e:
        return f"Error processing {filename}: {str(e)}"

def main():
    if len(sys.argv) < 2:
        print("Usage: identify_handshake.py <file1> [file2 ...]")
        print("       identify_handshake.py saved_client/*")
        return
    
    for filename in sys.argv[1:]:
        print(identify_handshake_file(filename))

if __name__ == "__main__":
    main()
