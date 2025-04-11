"""
HKDF (HMAC-based Key Derivation Function) implementation based on RFC 5869.
Used in TLS 1.3 as specified in RFC 8446.
"""

from hmac import HMAC

class HKDF:
    """
    HKDF (HMAC-based Key Derivation Function) class that implements
    the extract and expand functions as defined in RFC 5869.
    """
    
    def __init__(self, hash_func):
        """
        Initialize the HKDF with a hash function.
        
        Args:
            hash_func: A hash function like hashlib.sha256
        """
        self.hash_func = hash_func
        # Get hash length directly from the hash function
        self.hash_len = hash_func().digest_size
    
    def extract(self, salt, ikm):
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
    
    def expand(self, prk, info, length):
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