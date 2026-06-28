import requests, json, time, random
from rich import print
from libcrypto import Wallet
from libcrypto.addresses import AddressGenerator
from libcrypto.formats import private_key_to_wif, wif_to_private_key
from libcrypto.keys import PrivateKey
from libcrypto.bip32 import BIP32_HMAC_KEY
from libcrypto.mnemonic import mnemonic_to_seed, generate_mnemonic, mnemonic_to_entropy


def get_address_balance(address):
    """Fetches the balance of a given Bitcoin address."""
    try:
        req = requests.get(f"https://bitcoin.atomicwallet.io/api/address/{address}?details=basic").json()
        return int(req.get('balance', 0))
    except Exception as e:
        print(f"Error fetching balance for {address}: {e}")
        return 0


def get_address_transactions(address):
    """Fetches the number of transactions for a given Bitcoin address."""
    try:
        req = requests.get(f"https://bitcoin.atomicwallet.io/api/address/{address}?details=basic").json()
        return int(req.get('txApperances', 0))
    except Exception as e:
        print(f"Error fetching transactions for {address}: {e}")
        return 0


def get_current_time(fmt="%Y.%m.%d %H:%M:%S"):
    """Returns the current time in a specified format."""
    return time.strftime(fmt, time.localtime())


def generate_and_check_wallet():
    """Generates a new wallet, checks its addresses for balance and transactions, and logs findings."""
    mnemonic_words = generate_mnemonic(word_count=12)
    seed = mnemonic_to_seed(mnemonic_words)

    # normalize bytes to private key
    private_key_hex = seed[:32].hex()
    wif_compressed = private_key_to_wif(private_key=seed[:32], compressed=True, network='bitcoin')
    wif_uncompressed = private_key_to_wif(private_key=seed[:32], compressed=False, network='bitcoin')
    decimal_private_key = int(private_key_hex, 16)

    wallet = Wallet(private_key=seed[:32])
    addresses = wallet.get_all_addresses(coin='bitcoin')

    found_count = 0
    for address_type, address in addresses.items():
        transactions = get_address_transactions(address)
        print(f"{get_current_time()} - [green]INFO[/green] - [grey46]{address}[/grey46] - {transactions} - {mnemonic_words}")
        if transactions > 0:
            balance = get_address_balance(address)
            if balance > 0:
                found_count += 1
                log_finding(address, transactions, balance, mnemonic_words, private_key_hex, decimal_private_key, wif_compressed, wif_uncompressed)
            else:
                print(f"{get_current_time()} - INFO - Address: [green]{address}[/green] - TXS: {transactions} - Balance: {balance}")
    return found_count


def log_finding(address, transactions, balance, mnemonic, private_key, decimal_pk, wif_compressed, wif_uncompressed):
    """Logs details of a wallet with balance and transactions to a file and console."""
    with open("Found.txt", "a") as f:
        f.write(f"Address: {address} TXS: {transactions} Balance: {balance}\n"
                f"Mnemonic : {mnemonic}\n"
                f"Private Key: {private_key}\n"
                f"DEC: {decimal_pk}\n"
                f"WIF Compressed: {wif_compressed}\n"
                f"WIF Uncompressed: {wif_uncompressed}\n"
                f"Founded at: {get_current_time()}\n")

    print(f"Address: {address} TXS: {transactions} Balance: {balance}")
    print(f"Mnemonic : {mnemonic}")
    print(f"Private Key: {private_key}")
    print(f"DEC: {decimal_pk}")
    print(f"WIF Compressed: {wif_compressed}")
    print(f"WIF Uncompressed: {wif_uncompressed}")
    print()


# Main loop
total_checked = 0
total_found = 0
while True:
    total_checked += 1
    found_in_wallet = generate_and_check_wallet()
    total_found += found_in_wallet
    # You can add a small delay here if needed to avoid hitting API rate limits
    # time.sleep(1)