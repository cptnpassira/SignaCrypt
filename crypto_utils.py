from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.exceptions import InvalidSignature


def generate_keys():
    """
    Generate ECDSA private and public key pair using SECP256K1.
    """
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename="private_key.pem"):
    """
    Save private key to PEM file.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(pem)


def save_public_key(public_key, filename="public_key.pem"):
    """
    Save public key to PEM file.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)


def load_private_key(filename):
    """
    Load private key from PEM file.
    """
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(filename):
    """
    Load public key from PEM file.
    """
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_data(private_key, data: bytes):
    """
    Sign data using ECDSA + SHA256.
    """
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature(public_key, data: bytes, signature: bytes):
    """
    Verify ECDSA signature.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
