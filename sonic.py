import itertools
from functools import lru_cache
from binascii import hexlify
from mnemonic import Mnemonic
from ecdsa import SECP256k1, SigningKey
import threading
from Crypto.Hash import SHA256, RIPEMD

# Global variables
keys_scanned = 0
counter_lock = threading.Lock()

# Precompute the words list
with open("bip39.txt", "r") as f:
    BIP39_WORDS = f.read().splitlines()

mnemo = Mnemonic("english")

def generate_combinations(word_list):
    for combo in itertools.combinations(word_list, 2):
        yield combo

@lru_cache(maxsize=None)
def mnemonic_to_binary(mnemonic):
    entropy = mnemo.to_entropy(mnemonic)
    return bin(int.from_bytes(entropy, 'big'))[2:].zfill(len(entropy)*8)
    print({mnemonic})
@lru_cache(maxsize=None)
def binary_to_hex(binary_str):
    return hexlify(int(binary_str, 2).to_bytes((len(binary_str) + 7) // 8, byteorder='big')).decode()

def private_key_to_compressed_pubkey(private_key_bytes):
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_bytes = vk.to_string()
    if pubkey_bytes[-1] % 2 == 0:
        compressed_pubkey = b'\x02' + pubkey_bytes[:32]
    else:
        compressed_pubkey = b'\x03' + pubkey_bytes[:32]
    return compressed_pubkey

@lru_cache(maxsize=None)
def check_combination(mnemo, combination, hash160_set):
    global keys_scanned
    mnemonic_words = ["abandon"] * 21 + ["wood"] + list(combination)
    mnemonic = " ".join(mnemonic_words)
    
    with counter_lock:
        keys_scanned += 1
        if keys_scanned % 100000 == 0:
            print(f"Total keys scanned: {keys_scanned}")
    
    # Debug print statement to verify if mnemonics are being checked
    print(f"Checking mnemonic: {mnemonic}")
    
    if mnemo.check(mnemonic):
        # Print the valid mnemonic being processed
        print(f"Processing valid mnemonic: {mnemonic}")
        
        binary_rep = mnemonic_to_binary(mnemonic)
        private_key_bytes = int(binary_rep, 2).to_bytes((len(binary_rep) + 7) // 8, byteorder='big')
        compressed_pubkey = private_key_to_compressed_pubkey(private_key_bytes)
        hash160_value = compute_hash160_from_pubkey(compressed_pubkey)
        
        # Print the hash160 value for the valid mnemonic
        print(f"Hash160 for valid mnemonic '{mnemonic}': {hash160_value}")
        
        if hash160_value in hash160_set:
            print(f"Found the correct mnemonic for hash160 {hash160_value}: {mnemonic}")
            return mnemonic
    return None





def sequential_search():
    hash160_set = {
        "7d0f6c64afb419bbd7e971e943d7404b0e0daab4",
        "7025b4efb3ff42eb4d6d71fab6b53b4f4967e3dd",
        "2f396b29b27324300d0c59b17c3abc1835bd3dbb",
        "7ff45303774ef7a52fffd8011981034b258cb86b",
    }

    results = []
    word_combinations = generate_combinations(BIP39_WORDS)

    for combination in word_combinations:
        result = check_combination(mnemo, combination, hash160_set)
        if result:
            results.append(f"Found the correct mnemonic for hash160 {hash160_value}: {mnemonic}")

    # Write results to file in one go
    with open("founds.txt", "a") as file:
        file.writelines('\n'.join(results))

    print(f"Completed search. Scanned {keys_scanned} combinations.")

if __name__ == "__main__":
    sequential_search()
