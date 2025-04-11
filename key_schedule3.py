"""
TLS 1.3 Key Schedule Functions Implementation.

This module implements the Key Schedule functions defined in TLS 1.3 (RFC 8446).
"""

from key_schedule2 import HKDF

class KeyScheduleFunctions:
    """
    Implementation of TLS 1.3 Key Schedule Functions.
    
    This class implements the key schedule functions used in TLS 1.3:
    - HKDF-Expand-Label
    - Derive-Secret
    
    As defined in RFC 8446, Section 7.1.
    """
    
    def __init__(self, hash_func):
        """
        Initialize the KeyScheduleFunctions with a hash function.
        
        Args:
            hash_func: A hash function like hashlib.sha256
        """
        self.hash_func = hash_func
        self.hash_len = hash_func().digest_size
        self.hkdf = HKDF(hash_func)
    
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
        return self.hkdf.expand(secret, hkdf_label, length)
    
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