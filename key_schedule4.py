"""
TLS 1.3 Key Schedule Implementation.

This module implements the Key Schedule as defined in TLS 1.3 (RFC 8446).
"""

from key_schedule3 import KeyScheduleFunctions
from key_schedule2 import HKDF

class KeySchedule:
    """
    Implementation of the TLS 1.3 Key Schedule.
    
    This class handles the key schedule operations defined in TLS 1.3,
    maintaining state for PSK, DH shared secret, and handshake transcript.
    It calculates various secrets based on the current state.
    """
    
    def __init__(self, hash_func):
        """
        Initialize the KeySchedule with a hash function.
        
        Args:
            hash_func: A hash function like hashlib.sha256
        """
        self.hash_func = hash_func
        self.hash_len = hash_func().digest_size
        self.key_funcs = KeyScheduleFunctions(hash_func)
        self.hkdf = HKDF(hash_func)
        
        # Initialize the zero buffer used in multiple places
        self.zero = b'\x00' * self.hash_len
        
        # Public data members for secrets
        self.early_secret = None
        self.handshake_secret = None
        self.master_secret = None
        self.client_handshake_traffic_secret = None
        self.server_handshake_traffic_secret = None
        self.client_application_traffic_secret_0 = None
        self.server_application_traffic_secret_0 = None
        self.exporter_master_secret = None
        self.resumption_master_secret = None
        
        # State members
        self.psk = None
        self.dh_shared_secret = None
        self.transcript = b""
        
        # Initialize with default PSK (all zeros)
        self.set_PSK(self.zero)
    
    def set_PSK(self, psk):
        """
        Set the Pre-Shared Key and calculate early_secret.
        
        Args:
            psk: The Pre-Shared Key as bytes
        """
        self.psk = psk
        
        # Calculate early_secret
        self.early_secret = self.hkdf.extract(self.zero, self.psk)
    
    def set_DH_shared_secret(self, dh_shared_secret):
        """
        Set the DH shared secret and calculate handshake_secret and master_secret.
        
        Args:
            dh_shared_secret: The Diffie-Hellman shared secret as bytes
        """
        self.dh_shared_secret = dh_shared_secret
        
        # Derive the secret from early_secret
        derived_early = self.key_funcs.derive_secret(self.early_secret, b"derived", b"")
        
        # Calculate handshake_secret
        self.handshake_secret = self.hkdf.extract(derived_early, self.dh_shared_secret)
        
        # Calculate master_secret as well
        derived_handshake = self.key_funcs.derive_secret(self.handshake_secret, b"derived", b"")
        self.master_secret = self.hkdf.extract(derived_handshake, self.zero)
    
    def add_handshake(self, handshake_data):
        """
        Add handshake data to the transcript.
        
        Args:
            handshake_data: The handshake message as bytes
        """
        self.transcript += handshake_data
    
    def calc_handshake_traffic_secrets(self):
        """
        Calculate client and server handshake traffic secrets based on current transcript.
        
        Returns:
            A tuple of (client_handshake_traffic_secret, server_handshake_traffic_secret)
        """
        if not self.handshake_secret:
            raise ValueError("Handshake secret not yet established")
        
        self.client_handshake_traffic_secret = self.key_funcs.derive_secret(
            self.handshake_secret, 
            b"c hs traffic", 
            self.transcript
        )
        
        self.server_handshake_traffic_secret = self.key_funcs.derive_secret(
            self.handshake_secret, 
            b"s hs traffic", 
            self.transcript
        )
        
        return (self.client_handshake_traffic_secret, self.server_handshake_traffic_secret)    
    
    def calc_master_derived_secrets(self):
        """
        Calculate all master-derived secrets based on current transcript:
        - client_application_traffic_secret_0
        - server_application_traffic_secret_0
        - exporter_master_secret
        - resumption_master_secret
        
        Returns:
            A tuple of (client_application_traffic_secret_0, server_application_traffic_secret_0,
                        exporter_master_secret, resumption_master_secret)
        """
        if not self.master_secret:
            raise ValueError("Master secret not yet established, call set_DH_shared_secret first")
        
        # Calculate client and server application traffic secrets
        self.client_application_traffic_secret_0 = self.key_funcs.derive_secret(
            self.master_secret, 
            b"c ap traffic", 
            self.transcript
        )
        
        self.server_application_traffic_secret_0 = self.key_funcs.derive_secret(
            self.master_secret, 
            b"s ap traffic", 
            self.transcript
        )
        
        # Calculate exporter master secret
        self.exporter_master_secret = self.key_funcs.derive_secret(
            self.master_secret, 
            b"exp master", 
            self.transcript
        )
        
        # Calculate resumption master secret
        self.resumption_master_secret = self.key_funcs.derive_secret(
            self.master_secret, 
            b"res master", 
            self.transcript
        )
        
        return (
            self.client_application_traffic_secret_0,
            self.server_application_traffic_secret_0,
            self.exporter_master_secret,
            self.resumption_master_secret
        )
