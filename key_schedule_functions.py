"""
TLS 1.3 Key Schedule Functions Implementation.

This module implements the Key Schedule functions defined in TLS 1.3 (RFC 8446).
"""

from hmac import HMAC

class KeyScheduleFunctions:
    """
    Implementation of TLS 1.3 Key Schedule Functions.
    
    This class implements the key schedule functions used in TLS 1.3:
    - HKDF-Extract
    - HKDF-Expand
    - HKDF-Expand-Label
    - Derive-Secret
    
    As defined in RFC 8446, Section 7.1.
    """
    
    def __init__(self, hash_func, key_length=16, iv_length=12):
        """
        Initialize the KeyScheduleFunctions with a hash function.
        
        Args:
            hash_func: A hash function like hashlib.sha256
            key_length: Length of the key in bytes (default is 16 bytes/128 bits, suitable for AES-128)
            iv_length: Length of the IV in bytes (default is 12 bytes/96 bits, as required for AEAD)
        """
        self.hash_func = hash_func
        self.hash_len = hash_func().digest_size
        self.key_length = key_length
        self.iv_length = iv_length
    
    def HKDF_extract(self, salt, ikm):
        """
        HKDF-Extract function as defined in RFC 5869
        
        Args:
            salt: A non-secret random value used to extract entropy from ikm
                  If None or empty, it's replaced with a string of zeros
            ikm:  Input Keying Material (the secret input)
        
        Returns:
            A pseudorandom key (PRK) of Hash.length bytes
        """
        # If salt is not provided, set it to a string of zeros
        if salt is None or len(salt) == 0:
            salt = b'\x00' * self.hash_len
        
        # Extract: PRK = HMAC-Hash(salt, IKM)
        prk = HMAC(salt, ikm, self.hash_func).digest()
        
        return prk
    
    def HKDF_expand(self, prk, info, length):
        """
        HKDF-Expand function as defined in RFC 5869
        
        Args:
            prk: A pseudorandom key of at least Hash.length bytes (usually, the output from extract)
            info: Optional context and application specific information (can be zero-length)
            length: Length of output keying material in octets (<= 255*Hash.length)
        
        Returns:
            Output keying material (OKM) of length bytes
        """
        # Check that requested length is not too large
        if length > 255 * self.hash_len:
            raise ValueError("Length too large (maximum is 255*Hash.length)")
        
        # Calculate number of iterations required
        n = (length + self.hash_len - 1) // self.hash_len  # Ceiling division
        
        # Initialize output and T(0)
        T = b""
        T_prev = b""
        okm = b""
        
        # Perform iterations
        for i in range(1, n + 1):
            # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            counter = bytes([i])  # Ensure i is a single byte
            T = HMAC(prk, T_prev + info + counter, self.hash_func).digest()
            T_prev = T
            okm += T
        
        # Return the first 'length' bytes of the output
        return okm[:length]
    
    def _create_hkdf_label(self, length, label, context):
        """
        Create the HkdfLabel structure as defined in TLS 1.3.
        
        struct {
            uint16 length;
            opaque label<7..255> = "tls13 " + Label;
            opaque context<0..255> = Context;
        } HkdfLabel;
        
        Args:
            length: Length of the output key material
            label: The label string (should be bytes)
            context: The context value (should be bytes)
            
        Returns:
            The encoded HkdfLabel structure
        """
        # Prepend "tls13 " to the label
        full_label = b"tls13 " + label
        
        # Construct the HkdfLabel structure
        # length as uint16 (2 bytes, big-endian)
        hkdf_label = length.to_bytes(2, byteorder='big')
        
        # label length as one byte followed by the label
        hkdf_label += bytes([len(full_label)]) + full_label
        
        # context length as one byte followed by the context
        hkdf_label += bytes([len(context)]) + context
        
        return hkdf_label
    
    def hkdf_expand_label(self, secret, label, context, length):
        """
        HKDF-Expand-Label function as defined in TLS 1.3.
        
        HKDF-Expand-Label(Secret, Label, Context, Length) =
             HKDF-Expand(Secret, HkdfLabel, Length)
             
        Args:
            secret: The secret key material
            label: The label string as bytes
            context: The context value as bytes
            length: Length of the output key material
            
        Returns:
            The derived key material of specified length
        """
        hkdf_label = self._create_hkdf_label(length, label, context)
        return self.HKDF_expand(secret, hkdf_label, length)
    
    def derive_secret(self, secret, label, messages):
        """
        Derive-Secret function as defined in TLS 1.3.
        
        Derive-Secret(Secret, Label, Messages) =
             HKDF-Expand-Label(Secret, Label,
                              Transcript-Hash(Messages), Hash.length)
                              
        Args:
            secret: The secret key material
            label: The label string as bytes
            messages: The transcript messages to be hashed
            
        Returns:
            The derived secret of hash length
        """
        # Compute the transcript hash
        transcript_hash = self.hash_func(messages).digest()
        
        # Call HKDF-Expand-Label with the transcript hash as context
        return self.hkdf_expand_label(secret, label, transcript_hash, self.hash_len)
        
    def traffic_key_and_iv(self, traffic_secret):
        """
        Traffic Key Calculation as defined in TLS 1.3 (RFC 8446, Section 7.3).
        
        [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        
        Args:
            traffic_secret: The traffic secret (e.g., client_handshake_traffic_secret)
            
        Returns:
            A tuple of (key, iv) derived from the traffic secret
        """
        # Generate the traffic key
        key = self.hkdf_expand_label(traffic_secret, b"key", b"", self.key_length)
        
        # Generate the traffic IV
        iv = self.hkdf_expand_label(traffic_secret, b"iv", b"", self.iv_length)
        
        return key, iv