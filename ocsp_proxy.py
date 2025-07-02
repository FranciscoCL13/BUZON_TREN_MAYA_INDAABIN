import requests

def validar_ocsp_proxy(certificate_pem: str):
    url = "https://canvas-cnetservicios.buengobierno.gob.mx/dev/ocsp/verify"

    base64_cert = certificate_pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()

    data = {
        "certificado": base64_cert
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=data, headers=headers)

    if response.ok:
        return response.json()
    else:
        return {
            "resultado": "ERROR",
            "mensaje": f"Error {response.status_code}: {response.text}"
        }
