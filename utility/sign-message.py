import sys
import base64
import base58
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey, BadSignatureError

def wif_to_hex_private_key(wif: str) -> str:
    """
    Converts a Bitcoin WIF private key to a hexadecimal EC private key.

    Args:
        wif (str): The WIF private key.

    Returns:
        str: The EC private key in hexadecimal format.
    """
    # Decode WIF using Base58
    decoded = base58.b58decode(wif)

    # Verify checksum
    payload, checksum = decoded[:-4], decoded[-4:]
    calculated_checksum = sha256(sha256(payload).digest()).digest()[:4]
    if checksum != calculated_checksum:
        raise ValueError("Invalid WIF key: checksum does not match")

    # Remove prefix (first byte, 0x80) and optional compression flag (last byte if 0x01)
    private_key_bytes = payload[1:]
    if len(private_key_bytes) == 33 and private_key_bytes[-1] == 0x01:  # Compressed key
        private_key_bytes = private_key_bytes[:-1]

    # Convert to hex
    private_key_hex = private_key_bytes.hex()
    return private_key_hex

def sign_message(private_key_ec: str, message: str) -> str:
    """
    Sign the message from an EC private key with sign_deterministic().

    Args:
        private_key_ec (str): The EC hex private key.

    Returns:
        str: The signature in base64.
    """
    try:
        # Decode and remove the recovery ID (first byte)
        private_key_byte = bytes.fromhex(private_key_ec)

        # Init the SigningKey Object from bytes string
        private_key = SigningKey.from_string(private_key_byte, curve=SECP256k1, hashfunc=sha256)

        # Decode and hash the message
        data = sha256(message.encode()).digest()

        # Sign the message with the private key
        signature = private_key.sign_deterministic(data, sha256)
        return signature
        
    except BadSignatureError as e:
        print("BadSignature error")
    except MalformedSignature as e:
        print("MalformedSignature error")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: sign-message.py <message> <private-key>")
        print()
        print("The private-key has to be in the WIF format.")
        print("Eg. message-sign.py \"Who is John Galt?\" L21LJEeJwK35wby1BeTjwWssrhrgQE2MZrpTm2zbMC677czAHHu3")
        sys.exit(1)

    message = sys.argv[1] 
    private_key_wif = sys.argv[2]

    private_key_ec = wif_to_hex_private_key(private_key_wif)
    signature = sign_message(private_key_ec, message)
    base64_signature = base64.b64encode(signature).decode()
    print(base64_signature)
