import sys
import base64
from hashlib import sha256
from ecdsa import BadSignatureError, BadDigestError, VerifyingKey, SECP256k1


def verify_signature(message: str, signature: str, public_key: str) -> bool:
    """
    Verifies if the signed message was signed by the owner of the
    provided public key.

    Args:
        message (str): The original message.
        signature (str): The signed message (base64 encoded).
        public_key (str): Public key (hex encoded).

    Returns:
        bool: True if the signer owns the public key, False otherwise.
    """

    try:
        # Decode the signature from base64
        signature_bytes = base64.b64decode(signature)

        # Decode the public key from hex
        public_key_bytes = bytes.fromhex(public_key)

        # Convert to bytes
        data = message.encode()

        # Convert the public key to a VerifyingKey object
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1, hashfunc=sha256)
        return verifying_key.verify(signature_bytes, data, hashfunc=sha256)

    except BadSignatureError as e:
        # print(f"BadSignatureError:\n{e}")
        return False
    except BadDigestError as e:
        print(f"BadDigestError:\n{e}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: verify-signature.py <message> <signature> <public-key>")
        print()
        print("The public-key has to be in the EC hex format.")
        print("Eg.\nverify-signature.py IA/v1LkTm+VYnBxyakXWaYbAkKe6IhlaJs6dKPg+s7biGoHjU8f62fJEm1ALKXO/xZ/kgiFIQofSMeZMnSoXMuc= 030387cd9c823af50ef08bd7fee7cb4fbce7209975d11cee4be57807ad5949ddcc")
        sys.exit(1)

    message: str = sys.argv[1] 
    signature = sys.argv[2] 
    public_key_hex = sys.argv[3]

    result: bool = verify_signature(message, signature, public_key_hex) 
    if result:
        print("The signature is valid.")
    else:
        print("The signature is not valid or tampered.")
