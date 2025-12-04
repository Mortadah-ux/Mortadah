"""Simple file encryption and decryption utility.

Uses password-based key derivation (PBKDF2) with the `cryptography` library's
Fernet symmetric encryption. The output embeds a magic header and the random
salt so a single password can decrypt multiple files securely.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

MAGIC = b"ENC0"
SALT_SIZE = 16
ITERATIONS = 200_000


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _build_output(token: bytes, salt: bytes) -> bytes:
    return MAGIC + salt + token


def _parse_payload(data: bytes) -> Tuple[bytes, bytes]:
    if not data.startswith(MAGIC):
        raise ValueError("Input file does not appear to be encrypted with this utility.")
    salt = data[len(MAGIC): len(MAGIC) + SALT_SIZE]
    token = data[len(MAGIC) + SALT_SIZE:]
    if len(salt) != SALT_SIZE or not token:
        raise ValueError("Encrypted file is missing required components.")
    return token, salt


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Encrypt a file, writing the result to ``output_path``.

    The output embeds the salt so only the password is required to decrypt.
    """
    with open(input_path, "rb") as infile:
        plaintext = infile.read()

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext)

    with open(output_path, "wb") as outfile:
        outfile.write(_build_output(token, salt))


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a file created by ``encrypt_file``."""
    with open(input_path, "rb") as infile:
        payload = infile.read()

    token, salt = _parse_payload(payload)
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken as exc:
        raise ValueError("Incorrect password or corrupted file.") from exc

    with open(output_path, "wb") as outfile:
        outfile.write(plaintext)


def _prompt_password(arg_value: str | None) -> str:
    if arg_value is not None:
        return arg_value
    first = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if first != confirm:
        raise SystemExit("Passwords do not match.")
    return first


def _password_for_decrypt(arg_value: str | None) -> str:
    if arg_value is not None:
        return arg_value
    return getpass.getpass("Password: ")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Path to plaintext input file")
    enc_parser.add_argument("output", help="Path to write encrypted output")
    enc_parser.add_argument("--password", help="Password to use (prompted if omitted)")

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Path to encrypted input file")
    dec_parser.add_argument("output", help="Path to write decrypted output")
    dec_parser.add_argument("--password", help="Password to use (prompted if omitted)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "encrypt":
        password = _prompt_password(args.password)
        encrypt_file(args.input, args.output, password)
        print(f"Encrypted {args.input} -> {args.output}")
    else:
        password = _password_for_decrypt(args.password)
        decrypt_file(args.input, args.output, password)
        print(f"Decrypted {args.input} -> {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
