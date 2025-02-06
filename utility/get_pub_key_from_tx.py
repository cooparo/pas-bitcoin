import sys
from bitcoin import SelectParams
from bitcoin.core import lx
from bitcoin.rpc import JSONRPCError, Proxy


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

        print(f"\nRaw Transaction Details:\n{raw_tx}\n")

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
        print(f"Decoded ScriptSig: {decoded_script}")

        # Extract the public key from the scriptSig
        if len(decoded_script) < 2:
            raise ValueError(
                "scriptSig does not contain enough elements to extract a public key."
            )

        # The public key is typically the second item in the scriptSig
        pub_key = decoded_script[1]

        print(f"Raw pub key: {pub_key}")

        return pub_key

    except JSONRPCError as e:
        print(f"RPC Error: {e.error['message']}")
        raise e
    except Exception as e:
        print(f"Error: {str(e)}")
        raise e


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: get_pub_key_from_tx.py <transaction-id>")
        print()
        print(
            "Eg.\nget_pub_key_from_tx.py a6da1aab3e609026b9dbc38443924b315c103eb7f6638da6cb8fdc3e4ed5d383"
        )
        sys.exit(1)

    SelectParams("regtest")
    proxy = Proxy()

    tx_id = sys.argv[1]
    try:
        result = get_public_key(proxy, tx_id)
    except ValueError as e:
        raise e

    print(f"Pub key: {result}")
