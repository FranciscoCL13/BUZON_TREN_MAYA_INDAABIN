import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto

from pycfdi_credentials.utils import is_der, is_pem


class CertificateException(Exception):
    """Handle certificate load exceptions"""


@dataclass
class Subject:
    name: str
    rfc: str
    serial_number_used: str
    country_code: Optional[str] = None
    email: Optional[str] = None
    rfc_issuer: Optional[str] = None


class Certificate:
    class CertType(enum.Enum):
        FIEL = enum.auto()
        CSD = enum.auto()

    certificate: crypto.X509
    serial_number: str
    subject: Subject
    valid_not_before: datetime
    valid_not_after: datetime
    pub_key: bytes
    cert_type: CertType

    def __init__(self, certificate: bytes):
        self.certificate = self.bytes_to_x509(certificate)
        self.serial_number = self._get_serial_number()
        self.subject = self._get_subject()
        self.valid_not_before = self._get_valid_not_before()
        self.valid_not_after = self._get_valid_not_after()
        self.pub_key = self.get_pub_key(self.certificate)
        self.cert_type = self._get_cert_type()

    def _get_serial_number(self) -> str:
        hex_serial: int = self.certificate.get_serial_number()
        hex_repr: str = hex(hex_serial)
        hex_value: str = hex_repr[2:]
        return bytearray.fromhex(hex_value).decode()

    def _get_subject(self) -> Subject:
        subject_x509 = self.certificate.get_subject()
        x_500_unique_identifier = subject_x509.x500UniqueIdentifier  # type: ignore
        identifier_parts = x_500_unique_identifier.split("/")
        rfc = identifier_parts[0]
        rfc_issuer = identifier_parts[-1]
        rfc = rfc.strip()
        rfc_issuer = rfc_issuer.strip()
        return Subject(
            name=subject_x509.CN,
            country_code=subject_x509.C,
            email=subject_x509.emailAddress,
            rfc=rfc,
            serial_number_used=subject_x509.serialNumber,  # type: ignore
            rfc_issuer=rfc_issuer,
        )

    def _get_valid_not_before(self) -> datetime:
        not_before_str = self.certificate.get_notBefore().decode()  # type: ignore
        return datetime.strptime(not_before_str, "%Y%m%d%H%M%SZ")

    def _get_valid_not_after(self) -> datetime:
        not_after_str = self.certificate.get_notAfter().decode()  # type: ignore
        return datetime.strptime(not_after_str, "%Y%m%d%H%M%SZ")

    @staticmethod
    def get_pub_key(certificate: crypto.X509) -> bytes:
        pub = certificate.get_pubkey()
        cryptography_key = pub.to_cryptography_key()
        return cryptography_key.public_bytes(  # type: ignore
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def bytes_to_x509(content: bytes) -> crypto.X509:
        if is_der(content):
            return crypto.load_certificate(crypto.FILETYPE_ASN1, content)
        if is_pem(content):
            return crypto.load_certificate(crypto.FILETYPE_PEM, content)
        raise CertificateException("Not a valid certificate")

    def to_pem(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self.certificate)

    def to_der(self):
        return crypto.dump_certificate(crypto.FILETYPE_ASN1, self.certificate)

    def verify(self, signature: bytes, content, algorithm) -> bool:
        try:
            crypto.verify(self.certificate, signature, content, algorithm)
        except crypto.Error:
            # TODO log
            return False
        else:
            return True

    def _get_cert_type(self) -> CertType:
        subject_x509 = self.certificate.get_subject()
        if subject_x509.OU:
            return Certificate.CertType.CSD
        return Certificate.CertType.FIEL
