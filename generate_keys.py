from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate RSA key pair
    
    Returns:
        Tuple of (private_key, public_key) objects
    
    Implementation:
    - Use your language's crypto library to generate 4096-bit RSA key
    - Set public exponent to 65537
    - Serialize to PEM format
    - Return key objects for further use
    """
    
    # Generate private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    
    # Derive public key from private key
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_keypair_to_pem(private_key, public_key):
    """Save generated keys to PEM files."""
    
    # Save private key
    with open("student_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open("student_public.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    save_keypair_to_pem(private_key, public_key)
    print("Generated student_private.pem and student_public.pem")
