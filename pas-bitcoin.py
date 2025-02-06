import base64
from hashlib import sha256

from bitcoin import SelectParams
from bitcoin.core import lx
from bitcoin.rpc import JSONRPCError, Proxy
from ecdsa import BadDigestError, BadSignatureError, SECP256k1, VerifyingKey
from pyovpn.plugin import *

SIGN_MESSAGE = "Who is John Galt?"
BITCOIN_NETWORK = "regtest"
VPN_WALLET_NAME = "vpn"
USER_WALLET_NAME = "user"
WALLET_ALREADY_LOADED_ERROR_CODE = -35
WALLET_ALREADY_UNLOADED_ERROR_CODE = -18

AUTH_NULL = True
RETAIN_PASSWORD = True


def post_auth_cr(authcred, attributes, authret, info, crstate):
    # Debugging purpose
    print("**********************************************")
    print("AUTHCRED", authcred)
    print("ATTRIBUTES", attributes)
    print("AUTHRET", authret)
    print("INFO", info)
    print("**********************************************")

    # Don't do challenge/response on sessions or autologin clients.
    # autologin client: a client that has been issued a special
    #   certificate allowing authentication with only a certificate
    #   (used for unattended clients such as servers).
    # session: a client that has already authenticated and received
    #   a session token.  The client is attempting to authenticate
    #   again using the session token.
    if info.get("auth_method") in ("session", "autologin"):
        return authret

    # Check if this is a VPN authentication session
    if attributes.get("vpn_auth"):
        signature = authcred.get("static_response")
        # Get the dynamic response

        # Set the bitcoin network (regtest) for bitcoin rpc interaction
        SelectParams(BITCOIN_NETWORK)
        # Init proxy for rpc call to the bitcoin server
        proxy = Proxy()

        try:
            # Unload Bitcoin wallet of the user
            proxy.call("unloadwallet", USER_WALLET_NAME)
            # print(f"Wallet loaded: successfully")
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
            # print(f"Wallet loaded: successfully")
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

        sender_pub_keys = set()
        # Extract sender's public keys
        for tx_id in transaction_ids:
            pub_key = get_public_key(proxy, tx_id)
            if pub_key != 0x0 and pub_key != "0x0": # ignora le transazioni delle coinbase che non hanno pub_key
                sender_pub_keys.add(pub_key)

        print(f"Sender pub key: {sender_pub_keys}")
        # If no challenge response is provided, issue a challenge
        if signature:
            # received response
            print(f"Signature received: {signature}")
            # crstate.expire()

            # Default fail
            authret["status"] = FAIL
            authret["reason"] = "No matching signature"
            authret["client_reason"] = authret["reason"]

            # Verify matching signature with user's public key who paid
            for pub_key in sender_pub_keys:
                print(f"Checking public key: {pub_key}")
                if verify_signature(SIGN_MESSAGE, signature, pub_key):
                    authret["status"] = SUCCEED
                    authret["conn_group"] = "users"
                    authret["reason"] = "Signature matching successfull."
                    break
        else:
            # no signature provided
            print("Else")

            # Default failure, no signature provided
            authret["status"] = FAIL
            authret["reason"] = "No signature provided."
            authret["client_reason"] = (
                f"Pay at {to_pay_btc_address} and sign this message: Who is John Galt?"
            )

    return authret


def scan_transactions(proxy):
    """Scan for all transactions in a wallet and return a list of tx's IDs"""

    tx_ids = set()

    try:
        transaction_list = proxy.call("listtransactions")
    except JSONRPCError as e:
        raise e

    # Extract transaction's ids
    for tx in transaction_list:
        tx_ids.add(tx["txid"])

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


        if isinstance(pub_key, bytes):
            print("La variabile è di tipo bytes.")
            result = pub_key.hex()  # Converte bytes in hex
            print(f"Hex: {result}")
        elif isinstance(pub_key, int):
            print("La variabile è di tipo int.")
            result = hex(pub_key)  # Converte int in hex
            print(f"Hex: {result}")

        return result

    except JSONRPCError as e:
        print(f"RPC Error: {e.error['message']}")
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
        verifying_key = VerifyingKey.from_string(
            public_key_bytes, curve=SECP256k1, hashfunc=sha256
        )
        return verifying_key.verify(signature_bytes, data, hashfunc=sha256)

    except BadSignatureError as e:
        # print(f"BadSignatureError:\n{e}")
        return False
    except BadDigestError as e:
        print(f"BadDigestError:\n{e}")
