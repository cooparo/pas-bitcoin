from pyovpn.plugin import *
from bitcoin.rpc import Proxy, JSONRPCError
from bitcoin.core import lx
from bitcoin import SelectParams
import base64
from hashlib import sha256
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

SIGN_MESSAGE = "Who is John Galt?"
BITCOIN_NETWORK = "regtest"
VPN_WALLET_NAME = "vpn"
USER_WALLET_NAME = "user"
WALLET_ALREADY_LOADED_ERROR_CODE = -35
WALLET_ALREADY_UNLOADED_ERROR_CODE = -18

AUTH_NULL = True
RETAIN_PASSWORD = True

def post_auth(authcred, attributes, authret, info):

    # Check if this is a VPN authentication session
    if attributes.get("vpn_auth"):

        # Set the bitcoin network (regtest) for bitcoin rpc interaction
        SelectParams(BITCOIN_NETWORK)
        # Init proxy for rpc call to the bitcoin server
        proxy = Proxy()

        try:
            # Unload Bitcoin wallet of the user
            proxy.call("unloadwallet", USER_WALLET_NAME)
            #print(f"Wallet loaded: successfully")
        except JSONRPCError as e: 
            # Don't throw an error is the wallet is already loaded
            if e.error["code"] == WALLET_ALREADY_UNLOADED_ERROR_CODE: 
                print("User wallet unloaded successfully")
            else:
                print("Unloading user wallet failed")
                print(e)

        try:
            # Load Bitcoin wallet of the VPN
            proxy.call("loadwallet", VPN_WALLET_NAME)
            #print(f"Wallet loaded: successfully")
        except JSONRPCError as e: 
            # Don't throw an error is the wallet is already loaded
            if e.error["code"] == WALLET_ALREADY_LOADED_ERROR_CODE: 
                print("VPN wallet loaded successfully")
            else:
                print("Loading VPN wallet failed")
                print(e)

        try:
            # Get a new bitcoin address where the vpn's user can pay
            to_pay_btc_address = proxy.getnewaddress()
        except JSONRPCError as e:
            print("Retrieving new address failed.")
            print(e)

        try:
            # Get all transaction ids
            transaction_ids = scan_transactions(proxy)
        except JSONRPCError as e:
            print("Scanning transaction failed")
            print(e)

        sender_pub_keys = []
        # Extract sender's public keys
        for tx_id in transaction_ids:
            pub_key = get_public_key(proxy, tx_id)
            sender_pub_keys.append(pub_key)

        # If no challenge response is provided, issue a challenge
        if "static_response" not in authcred:
            print("Inside not static_response")
            # Default failure, no signature provided
            authret["status"] = FAIL
            authret["reason"] = "Not payment yet or no matching signature."
            authret["client_reason"] = (
                f"Pay to: {to_pay_btc_address} and sign this message with your private key: {SIGN_MESSAGE}."
            )   
        else:
            # Validate the challenge response 
            print("Else")
            signature = authcred["static_response"]
            print(f"Received signature: {signature}")

            print(f"Scanned pub keys: {sender_pub_keys}")
            # For each incoming payment, check sender pub key with the signature
            authret["status"] = FAIL
            authret["reason"] = "User has no valid signature or payment done"  
            authret["client_reason"] = "No valid signature or did not payed"

            for pub_key in sender_pub_keys:
                if verify_signature(SIGN_MESSAGE, signature, pub_key):
                    authret["status"] = SUCCEED
                    authret["conn_group"] = "users"  
                    authret["reason"] = "User has valid signature"  
                    authret["client_reason"] = "Valid signature."
                    break

    return authret


def scan_transactions(proxy):
    """Scan for all transactions in a wallet and return a list of tx's IDs"""

    tx_ids = []

    try:
        transaction_list = proxy.call("listtransactions")
    except JSONRPCError as e:
        raise e

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
        print(f"RPC Error: {e.error["message"]}")
        raise e
    except Exception as e:
        print(f"Error: {str(e)}")
        raise e


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
