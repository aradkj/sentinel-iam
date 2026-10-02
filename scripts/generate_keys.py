#!/usr/bin/env python3
"""Generate a 2048-bit RSA keypair (private.pem and public.pem) for local RS256 development."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = output_dir / "private.pem"
    public_path = output_dir / "public.pem"
    private_path.write_bytes(private_pem)
    private_path.chmod(0o600)
    public_path.write_bytes(public_pem)
    return private_path, public_path


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    priv, pub = generate_rsa_keypair(root / "keys")
    print(f"Generated RSA private key: {priv}")
    print(f"Generated RSA public key:  {pub}")
