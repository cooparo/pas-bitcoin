from bitcoin.rpc import Proxy, JSONRPCError
from bitcoin.core import lx
from bitcoin import SelectParams

BITCOIN_NETWORK = "regtest"

VPN_WALLET_NAME = "vpn"
USER_WALLET_NAME = "user"

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
        # Load Bitcoin wallet of the user
        proxy.call("loadwallet", USER_WALLET_NAME)

    except JSONRPCError as e: 
        # Don't throw an error is the wallet is already loaded
        if e.error["code"] != WALLET_ALREADY_LOADED_ERROR_CODE: 
            print("Loading VPN wallet failed")
        else: raise e

    try:
        txid = proxy.sendtoaddress(bitcoin_address, amount)
    except JSONRPCError as e:
        print("Payment failed.")
        raise e
    
    print(f"Successfully payed, txid:\n{txid}")


