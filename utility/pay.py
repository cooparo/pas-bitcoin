from bitcoin.rpc import Proxy, JSONRPCError
from bitcoin.core import lx
from bitcoin import SelectParams
import hashlib
import base58
import sys

BITCOIN_NETWORK = "regtest"

VPN_WALLET_NAME = "vpn"
USER_WALLET_NAME = "user"
WALLET_ALREADY_LOADED_ERROR_CODE = -35
WALLET_ALREADY_UNLOADED_ERROR_CODE = -18

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

def ec_to_address(ec_point: str) -> str:
    """Convert a compressed or uncompressed EC public key to a Bitcoin address."""
    BITCOIN_NETWORK_BYTE = b'\x6F'
    
    # Step 1: SHA-256 hashing of the public key
    pubkey_bytes = bytes.fromhex(ec_point)
    sha256_pubkey = hashlib.sha256(pubkey_bytes).digest()
    
    # Step 2: RIPEMD-160 hashing of the SHA-256 hash
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pubkey)
    hashed_pubkey = ripemd160.digest()
    
    # Step 3: Add network byte (0x00 for Bitcoin mainnet, 0x6F for testnet)
    extended_key = BITCOIN_NETWORK_BYTE + hashed_pubkey
    
    # Step 4: Compute the checksum (SHA-256 twice)
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    
    # Step 5: Append checksum
    binary_address = extended_key + checksum
    
    # Step 6: Base58 encode
    address = base58.b58encode(binary_address).decode('utf-8')
    return address

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: pay.py <btc-address> <amount>")
        print()
        print("Eg.\npay.py mxj8XkfYgEHP31Ln5PWvmvXgQdT5vHDxNR 10.0")
        sys.exit(1)

    bitcoin_address = sys.argv[1]
    amount = sys.argv[2]
    
    # Define network 
    SelectParams(BITCOIN_NETWORK)
    proxy = Proxy()

    try:
        # Unload Bitcoin wallet of the VPN
        proxy.call("unloadwallet", VPN_WALLET_NAME)
    except JSONRPCError as e: 
        # Don't throw an error is the wallet is already unloaded
        if e.error["code"] != WALLET_ALREADY_UNLOADED_ERROR_CODE: 
            print("Unloading VPN wallet failed.")
            raise e

    try:
        # Load Bitcoin wallet of the user
        proxy.call("loadwallet", USER_WALLET_NAME)
    except JSONRPCError as e: 
        # Don't throw an error is the wallet is already loaded
        if e.error["code"] != WALLET_ALREADY_LOADED_ERROR_CODE: 
            print("Loading USER wallet failed.")
            raise e

    print("Wallet successfully loaded.")

    try:
        txid = proxy.call(
            "sendtoaddress",
            bitcoin_address, # address
            amount, # amount
            "", # comment
            "", # comment_to
            False, # subtractfeefromamount
            False, # replaceable
            6, # conf_target
            "conservative", # estimate_mode
            False, # avoid_reuse
            # 1.0 # fee_rate
        )
    except JSONRPCError as e:
        print("Payment failed.")
        raise e
    
    print(f"Successfully payed, txid: {txid}")

    ec_pub_key = get_public_key(proxy, txid)
    # print(f"EC pub key: {ec_pub_key}")

    address = ec_to_address(ec_pub_key)
    # print(f"Address: {address}")

    priv_key = proxy.dumpprivkey(address)
    print(f"Private key: {priv_key}")
