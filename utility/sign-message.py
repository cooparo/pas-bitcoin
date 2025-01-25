import sys
import base64
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey, BadSignatureError

def sign_message(private_key_wif: str, message: str):
    try:
        private_key_byte = bytes.fromhex(private_key_wif)[1:]
        private_key = SigningKey.from_string(private_key_byte, curve=SECP256k1, hashfunc=sha256)

        data = sha256(message.encode()).digest()
        signature = private_key.sign_deterministic(data, sha256)
        return signature
    except BadSignatureError as e:
        raise e
    except MalformedSignature as e:
        raise e

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: sign-message.py <message> <private-key>")
        print()
        print("The private-key has to be in the WIF format.")
        print("Eg. message-sign.py \"Who is John Galt?\" L21LJEeJwK35wby1BeTjwWssrhrgQE2MZrpTm2zbMC677czAHHu3")
        sys.exit(1)

    message = sys.argv[1] 
    private_key = sys.argv[2]

    signature = sign_message(private_key, message)
    base64_signature = base64.b64encode(signature).decode()
    print(base64_signature)
