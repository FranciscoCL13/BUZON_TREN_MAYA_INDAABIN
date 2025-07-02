import base64
import textwrap


def is_der(content: bytes) -> bool:
    """
    Check if the content is a DER format
    """
    return content[:2] == b"\x30\x82"


def is_pem(content: bytes) -> bool:
    """
    Check if the content is a PEM format
    """
    return content.startswith(b"-----BEGIN")


def read_file(path: str) -> bytes:
    """
    Read a file and return its content
    """
    with open(path, "rb") as file:
        return file.read()


def der_to_pem(der_content: bytes, header: str) -> bytes:
    """
    Convert DER to PEM
    """
    der_b64 = base64.b64encode(der_content).decode("utf-8")
    wrapped = "\n".join(textwrap.wrap(der_b64, 64))
    return f"""\
-----BEGIN {header}-----
{wrapped}
-----END {header}-----\
""".encode(
        "UTF-8"
    )


def pem_to_der(pem_content_bytes: bytes) -> bytes:
    """
    Convert PEM to DER
    """
    pem_content = pem_content_bytes.decode("utf-8")
    headers = (
        "CERTIFICATE",
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    )
    for header in headers:
        pem_content = pem_content.replace(f"-----BEGIN {header}-----", "")
        pem_content = pem_content.replace(f"-----END {header}-----", "")
    pem_content = pem_content.replace("\n", "")
    pem_content = pem_content.replace("\r", "")
    pem_content = pem_content.replace("\t", "")
    return base64.b64decode(pem_content.encode("utf-8"))
