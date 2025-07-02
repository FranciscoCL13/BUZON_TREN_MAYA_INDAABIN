from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto

from pycfdi_credentials.utils import der_to_pem, is_der, is_pem


class PrivateKeyException(Exception):
    """Handle private key load exceptions"""


class PrivateKey:
    private_key: crypto.PKey
    passphrase: bytes
    content: bytes

    def __init__(self, content: bytes, passphrase: bytes = b""):
        if isinstance(passphrase, str):
            passphrase = str(passphrase).encode()
        self.passphrase = passphrase
        try:
            private_key_uncrypted = self.load_private_key(content, passphrase)
        except crypto.Error as exception:
            raise PrivateKeyException(
                "Error loading the key, maybe the passphrase is wrong"
            ) from exception
        self.private_key = private_key_uncrypted  # Warning, this object is not encrypted
        self.content = content

    @staticmethod
    def load_private_key(content: bytes, passphrase: bytes = None):
        if is_der(content):
            header = "ENCRYPTED PRIVATE KEY" if passphrase else "PRIVATE KEY"
            content = der_to_pem(content, header)
        if is_pem(content):
            private_key_uncrypted = crypto.load_privatekey(
                crypto.FILETYPE_PEM, content, passphrase=passphrase
            )
        else:
            raise PrivateKeyException("Not a valid key")
        return private_key_uncrypted

    def to_pem(self, passphrase: bytes = None):
        """
        Export the private key to PEM format
        """
        cipher = "aes256" if passphrase else None
        return crypto.dump_privatekey(
            crypto.FILETYPE_PEM, self.private_key, cipher=cipher, passphrase=passphrase
        )

    def sign(self, content: bytes, algorithm) -> bytes:
        """
        Sign a content with the private key
        """
        return crypto.sign(self.private_key, content, algorithm)

    def is_equivalent(self, other: "PrivateKey") -> bool:
        """
        Compare this private key with another one
        """
        cryp_key = self.private_key.to_cryptography_key()
        other_cryp_key = other.private_key.to_cryptography_key()
        private_bytes = cryp_key.private_bytes(  # type: ignore
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        other_private_bytes = other_cryp_key.private_bytes(  # type: ignore
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return private_bytes == other_private_bytes
