#       HKDF-Expand-Label(Secret, Label, Context, Length) =
#            HKDF-Expand(Secret, HkdfLabel, Length)
#
#       Where HkdfLabel is specified as:
#
#       struct {
#           uint16 length = Length;
#           opaque label<7..255> = "tls13 " + Label;
#           opaque context<0..255> = Context;
#       } HkdfLabel;
#
#       Derive-Secret(Secret, Label, Messages) =
#            HKDF-Expand-Label(Secret, Label,
#                              Transcript-Hash(Messages), Hash.length)

from hmac import HMAC

def HKDF_extract(salt, ikm, hash_name='sha256'):
    """
    HKDF-Extract function as defined in RFC 5869 and used in TLS 1.3 (RFC 8446)
    
    Args:
        salt: A non-secret random value used to extract entropy from ikm
              If None or empty, it's replaced with a string of zeros
        ikm:  Input Keying Material (the secret input)
        hash_name: The hash function to use (default: 'sha256')
    
    Returns:
        A pseudorandom key (PRK) of Hash.length bytes
    """
    # Get hash length based on algorithm
    hash_lengths = {'sha256': 32, 'sha384': 48, 'sha512': 64}
    hash_len = hash_lengths.get(hash_name, 32)
    
    # If salt is not provided, set it to a string of zeros
    if salt is None or len(salt) == 0:
        salt = b'\x00' * hash_len
    
    # Ensure inputs are bytes
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    if isinstance(ikm, str):
        ikm = ikm.encode('utf-8')
    
    # Extract: PRK = HMAC-Hash(salt, IKM)
    prk = HMAC(salt, ikm, hash_name).digest()
    
    return prk

def HKDF_expand(prk, info, length, hash_name='sha256'):
    """
    HKDF-Expand function as defined in RFC 5869 and used in TLS 1.3 (RFC 8446)
    
    Args:
        prk: A pseudorandom key of at least Hash.length bytes (usually, the output from HKDF-Extract)
        info: Optional context and application specific information (can be zero-length)
        length: Length of output keying material in octets (<= 255*Hash.length)
        hash_name: The hash function to use (default: 'sha256')
    
    Returns:
        Output keying material (OKM) of length bytes
    """
    # Get hash length based on algorithm
    hash_lengths = {'sha256': 32, 'sha384': 48, 'sha512': 64}
    hash_len = hash_lengths.get(hash_name, 32)
    
    # Check that requested length is not too large
    if length > 255 * hash_len:
        raise ValueError("Length too large (maximum is 255*Hash.length)")
    
    # Ensure inputs are bytes
    if isinstance(prk, str):
        prk = prk.encode('utf-8')
    if isinstance(info, str):
        info = info.encode('utf-8')
    
    # Calculate number of iterations required
    n = (length + hash_len - 1) // hash_len  # Ceiling division
    
    # Initialize output and T(0)
    T = b""
    T_prev = b""
    okm = b""
    
    # Perform iterations
    for i in range(1, n + 1):
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        counter = bytes([i])  # Ensure i is a single byte
        T = HMAC(prk, T_prev + info + counter, hash_name).digest()
        T_prev = T
        okm += T
    
    # Return the first 'length' bytes of the output
    return okm[:length]


import hashlib

def HKDF_expand_label(secret, label, context, length, hash_name='sha256'):
    """
    HKDF-Expand-Label function as defined in TLS 1.3 (RFC 8446)
    
    Args:
        secret: The key material to expand
        label: A label to include in the expansion
        context: Context value (usually a transcript hash)
        length: Length of output keying material in octets
        hash_name: The hash function to use (default: 'sha256')
    
    Returns:
        Expanded key material of specified length
    """
    # Ensure inputs are bytes
    if isinstance(label, str):
        label = label.encode('utf-8')
    if isinstance(context, str):
        context = context.encode('utf-8')
    
    # Prepare the HkdfLabel structure:
    # struct {
    #     uint16 length = Length;
    #     opaque label<7..255> = "tls13 " + Label;
    #     opaque context<0..255> = Context;
    # } HkdfLabel;
    
    hkdf_label = (length.to_bytes(2, byteorder='big') + 
                 len(b"tls13 " + label).to_bytes(1, byteorder='big') + 
                 b"tls13 " + label +
                 len(context).to_bytes(1, byteorder='big') + 
                 context)
    
    return HKDF_expand(secret, hkdf_label, length, hash_name)

def transcript_hash(messages, hash_name='sha256'):
    """
    Calculate the transcript hash of a sequence of messages
    
    Args:
        messages: A list of message bytes or a single message
        hash_name: The hash function to use (default: 'sha256')
    
    Returns:
        Hash of the concatenated messages
    """
    hash_obj = hashlib.new(hash_name)
    
    # If messages is None or empty, return hash of empty string
    if messages is None:
        return hash_obj.digest()
    
    # Handle both single message and list of messages
    if isinstance(messages, list):
        for message in messages:
            if isinstance(message, str):
                message = message.encode('utf-8')
            hash_obj.update(message)
    else:
        if isinstance(messages, str):
            messages = messages.encode('utf-8')
        hash_obj.update(messages)
    
    return hash_obj.digest()

def derive_secret(secret, label, messages, hash_name='sha256'):
    """
    Derive-Secret function as defined in TLS 1.3 (RFC 8446)
    
    Args:
        secret: The key material to derive from
        label: A label string to include in the derivation
        messages: The transcript of handshake messages or None for empty transcript
        hash_name: The hash function to use (default: 'sha256')
    
    Returns:
        Derived secret material
    """
    # Get hash length based on algorithm
    hash_lengths = {'sha256': 32, 'sha384': 48, 'sha512': 64}
    hash_len = hash_lengths.get(hash_name, 32)
    
    # Calculate the transcript hash of the messages
    message_hash = transcript_hash(messages, hash_name)
    
    # Derive-Secret(Secret, Label, Messages) =
    #     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    return HKDF_expand_label(secret, label, message_hash, hash_len, hash_name)

#             0
#             |
#             v
#   PSK ->  HKDF-Extract = Early Secret
#             |
#             +-----> Derive-Secret(., "ext binder" | "res binder", "")
#             |                     = binder_key
#             |
#             +-----> Derive-Secret(., "c e traffic", ClientHello)
#             |                     = client_early_traffic_secret
#             |
#             +-----> Derive-Secret(., "e exp master", ClientHello)
#             |                     = early_exporter_master_secret
#             v
#       Derive-Secret(., "derived", "")
#             |
#             v
#   (EC)DHE -> HKDF-Extract = Handshake Secret
#             |
#             +-----> Derive-Secret(., "c hs traffic",
#             |                     ClientHello...ServerHello)
#             |                     = client_handshake_traffic_secret
#             |
#             +-----> Derive-Secret(., "s hs traffic",
#             |                     ClientHello...ServerHello)
#             |                     = server_handshake_traffic_secret
#             v
#       Derive-Secret(., "derived", "")
#             |
#             v
#   0 -> HKDF-Extract = Master Secret
#             |
#             +-----> Derive-Secret(., "c ap traffic",
#             |                     ClientHello...server Finished)
#             |                     = client_application_traffic_secret_0
#             |
#             +-----> Derive-Secret(., "s ap traffic",
#             |                     ClientHello...server Finished)
#             |                     = server_application_traffic_secret_0
#             |
#             +-----> Derive-Secret(., "exp master",
#             |                     ClientHello...server Finished)
#             |                     = exporter_master_secret
#             |
#             +-----> Derive-Secret(., "res master",
#                                   ClientHello...client Finished)
#                                   = resumption_master_secret

from pathlib import Path

def read_bytes(filename):
    return Path("sample_data/server_openssl_client/saved_server/" + filename).read_bytes()

#import re
#def read_handshake_bytes():
#    idx_to_name = {}
#    for item in Path("sample_data/server_openssl_client/saved_server").iterdir():
#        match = re.search(r"_handshake_(\d+)$", item.name)
#        if match:
#            idx_to_name[match.group(1)] = item.name
#
#    print(idx_to_name)
#    result = []
#    idx = 0
#    while True:
#        result.append(read_bytes(idx_to_name[str(idx)]))
#        if result[idx][0] == 20: # Finished
#            return result
#        idx += 1
#
#handshake_bytes = read_handshake_bytes()

handshake_bytes = [
    read_bytes("000_handshake_0"), # client_hello (1)
    read_bytes("004_handshake_1"), # server_hello (2)
    read_bytes("009_handshake_2"), # encrypted_extensions (8)
    read_bytes("010_handshake_3"), # certificate (11)
    read_bytes("011_handshake_4"), # certificate_verify (15)
    read_bytes("012_handshake_5"), # finished (20) <== server Finished
] 

hash_length = 32
zero = b'\x00' * hash_length
PSK = b'\x00' * hash_length

early_secret = HKDF_extract(zero, PSK)
print("early_secret: ", early_secret.hex())
assert early_secret == read_bytes("005_early_secret")

client_hello = handshake_bytes[0]
dh_shared_secret = read_bytes("003_dh_shared_secret")

d1 = derive_secret(early_secret, b"derived", b"")

handshake_secret = HKDF_extract(d1, dh_shared_secret)
print("handshake_secret: ", handshake_secret.hex())
assert handshake_secret == read_bytes("006_handshake_secret")

server_hello = handshake_bytes[1]
client_handshake_traffic_secret = derive_secret(handshake_secret, b"c hs traffic", client_hello + server_hello)
print("client_handshake_traffic_secret: ", client_handshake_traffic_secret.hex())
assert client_handshake_traffic_secret == read_bytes("008_client_handshake_traffic_secret")

server_handshake_traffic_secret = derive_secret(handshake_secret, b"s hs traffic", client_hello + server_hello)
print("server_handshake_traffic_secret: ", server_handshake_traffic_secret.hex())
assert server_handshake_traffic_secret == read_bytes("007_server_handshake_traffic_secret")

d2 = derive_secret(handshake_secret, b"derived", b"")
master_secret = HKDF_extract(d2, zero)
print("master_secret: ", master_secret.hex())
assert master_secret == read_bytes("013_master_secret")

handshake_all = b''.join(handshake_bytes)

client_application_traffic_secret_0 = derive_secret(master_secret, b"c ap traffic", handshake_all)
print("client_application_traffic_secret_0: ", client_application_traffic_secret_0.hex())
assert client_application_traffic_secret_0 == read_bytes("014_client_application_traffic_secret_0")

server_application_traffic_secret_0 = derive_secret(master_secret, b"s ap traffic", handshake_all)
print("server_application_traffic_secret_0: ", server_application_traffic_secret_0.hex())
assert server_application_traffic_secret_0 == read_bytes("015_server_application_traffic_secret_0")

print("compare with keylog.txt:")
import subprocess
subprocess.run(["grep", "-i", server_application_traffic_secret_0.hex(), "sample_data/server_openssl_client/keylog.txt"], check=True)