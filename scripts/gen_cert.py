import os, sys
from datetime import datetime, timedelta, UTC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_cert(name):
    os.makedirs("certs", exist_ok=True)

    # Load CA
    with open("certs/ca.key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("certs/ca.crt.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Generate keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{name}-Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    with open(f"certs/{name}.key.pem", "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(f"certs/{name}.crt.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✅ Certificate generated for {name}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/gen_cert.py <client|server>")
        sys.exit(1)
    generate_cert(sys.argv[1])
