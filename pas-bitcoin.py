from pyovpn.plugin import *
from bitcoin.rpc import Proxy, JSONRPCError
from bitcoin.core import lx
from bitcoin import SelectParams
import base64
from hashlib import sha256
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

SIGN_MESSAGE = "Who is John Galt?"
BITCOIN_NETWORK = "regtest"

AUTH_NULL = True
RETAIN_PASSWORD = True

def post_auth(authcred, attributes, authret, info):
    
    # Failure, no matching in signature-pubkey payment
    authret["status"] = FAIL
    authret["client_reason"] = ("No payment provided for this private key")   
    
    # No authentication needed for admins
    if authcred['username'] == 'openvpn': 
        authret['conn_group'] = 'admins' # Assign user to VPN_USERS group
        authret["client_reason"] = ("You are an admin")
        authret['status'] = SUCCEED
        return authret

    # Set the bitcoin network (regtest) for bitcoin rpc interaction
    SelectParams(BITCOIN_NETWORK)
    # Init proxy for rpc call to the bitcoin server
    proxy = Proxy()

    to_pay_btc_address = proxy.getnewaddress()

    # Load Bitcoin wallet
    try:
        proxy.call("loadwallet", "vpn")
        #print(f"Wallet loaded: successfully")
    except JSONRPCError as e:
        if e.error["code"] != -35:
            raise e

    # Get all transaction ids
    transaction_ids = scan_transactions(proxy)

    sender_pub_keys = []
    # Extract sender's public keys
    for tx_id in transaction_ids:
        pub_key = get_public_key(proxy, tx_id)
        sender_pub_keys.append(pub_key)

    # Check if this is a VPN authentication session
    if attributes.get("vpn_auth"):
        # Validate the challenge response (implement custom logic here)
        if "static_response" in authcred:
            signature = authcred["static_response"]
            print(f"Received signature: {signature}")

            print(f"Scanned pub keys: {sender_pub_keys}")
            # For each incoming payment, check sender pub key with the signature
            for pub_key in sender_pub_keys:
                if verify_signature(SIGN_MESSAGE, signature, pub_key):
                    authret["status"] = SUCCEED
                    authret['conn_group'] = 'users'  
                    authret["client_reason"] = "Valid signature."
        else:
            # Default failure, no signature provided
            authret["status"] = FAIL
            authret["client_reason"] = (
                f"Pay to: {to_pay_btc_address} and sign this message with your private key: {SIGN_MESSAGE}"
            )   

    return authret


def scan_transactions(proxy):
    """Scan for all transactions in a wallet and return a list of tx's IDs"""

    tx_ids = []
    transaction_list = proxy.call("listtransactions")
    # print(f"raw_transaction_list:\n{raw_transaction_list}")

    # Extract transaction's ids
    for tx in transaction_list:
        tx_ids.append(tx["txid"])

    return tx_ids


def get_public_key(proxy, transaction_id):
    """
    Retrieve the public key of the sender from a transaction ID.

    Args:
        proxy: The Bitcoin RPC proxy.
        transaction_id (str): The transaction ID.

    Returns:
        str: The sender's public key in hexadecimal format.
    """
    try:
        # Convert the transaction ID to bytes
        bytes_tx = lx(transaction_id)

        # Get the raw transaction details (decoded JSON)
        raw_tx = proxy.getrawtransaction(bytes_tx, True)

        # print(f"\nRaw Transaction Details:\n{raw_tx}\n")

        # Extract the transaction object
        tx = raw_tx["tx"]  # Access the 'tx' key for the actual transaction data

        # Ensure there is at least one input
        if not tx.vin or len(tx.vin) == 0:
            raise ValueError("Transaction has no inputs.")

        # Get the first input
        vin = tx.vin[0]

        # Ensure the input contains scriptSig
        if not vin.scriptSig or len(vin.scriptSig) == 0:
            raise ValueError("Transaction input does not contain a valid scriptSig.")

        # Decode the scriptSig
        script_sig = vin.scriptSig
        decoded_script = list(script_sig)
        # print(f"Decoded ScriptSig: {decoded_script}")

        # Extract the public key from the scriptSig
        if len(decoded_script) < 2:
            raise ValueError(
                "scriptSig does not contain enough elements to extract a public key."
            )

        # The public key is typically the second item in the scriptSig
        pub_key = decoded_script[1]

        return pub_key.hex()

    except JSONRPCError as e:
        print(f"RPC Error: {e.error['message']}")
        raise e
    except Exception as e:
        print(f"Error: {str(e)}")
        raise e


# NOTE: This way of hashing the message is needed for compatibility
# with all that signature bitcoin related tools (bx, bitcoin core)
def bitcoin_message_hash(message: str) -> bytes:
    """
    Hash the message with the Bitcoin Signed Message prefix.
    """
    prefix = (
        b"\x18Bitcoin Signed Message:\n"  # called Magic Prefix (or strMessageMagic)
    )
    message_bytes = message.encode()
    length = len(message_bytes).to_bytes(1, byteorder="big")
    return sha256(sha256(prefix + length + message_bytes).digest()).digest()


def verify_signature(message: str, signature: str, public_key: str) -> bool:
    """
    Verifies if the signed message was signed by the owner of the
    provided public key.

    Args:
        message (str): The original message.
        signature (str): The signed message (base64 encoded).
        public_key (str): Compressed public key (hex encoded).

    Returns:
        bool: True if the signer owns the public key, False otherwise.
    """
    try:
        # Decode the signature from base64 and remove the
        # recovery ID (first byes)
        decoded_signature = base64.b64decode(signature)[1:]

        # Decode the public key
        decoded_pub_key = bytes.fromhex(public_key)

        # Hash the message with the Bitcoin Signed Message prefix
        hashed_message = bitcoin_message_hash(message)

        # Convert the public key to a VerifyingKey object
        verifying_key = VerifyingKey.from_string(decoded_pub_key, curve=SECP256k1)

        return verifying_key.verify_digest(decoded_signature, hashed_message)

    except (BadSignatureError, ValueError):
        return False  # Signature verification failed
    except Exception as e:
        print(f"Error processing public key {public_key}: {e}")
        raise e
