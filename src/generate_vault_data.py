import base64
import json
import io
import pandas as pd
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number

# ---- 1. Sample Data Setup ----
df = pd.read_csv('data/paysim.csv')

# ---- 2. Generate Weak Key Pair via Package Primitives ----
print(
    "[*] Generating RSA-512 keypair (legacy bank key, unbalanced primes)..."
)


def gen_weak_rsa_512():
    e = 65537
    while True:
        p = number.getPrime(200)
        q = number.getPrime(312)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if number.GCD(e, phi) == 1:
            d = number.inverse(e, phi)
            # Standard package construct: wraps manual math into a valid Crypto.PublicKey object
            return RSA.construct((n, e, d, p, q))


key = gen_weak_rsa_512()
public_key = key.publickey()
cipher = PKCS1_OAEP.new(public_key)

# ---- 3. Process CSV Rows into Encrypted Vault ----
print(f"[*] Processing {len(df)} records from PaySim dataset...")
vault_txns = []

for idx, row in df.iterrows():
    # Construct plaintext record payload from the CSV features
    plaintext_dict = {
        "nameOrig": str(row["nameOrig"]),
        "nameDest": str(row["nameDest"]),
        "amount": float(row["amount"]),
        "oldbalanceOrg": float(row["oldbalanceOrg"]),
        "newbalanceOrig": float(row["newbalanceOrig"]),
        "oldbalanceDest": float(row["oldbalanceDest"]),
        "newbalanceDest": float(row["newbalanceDest"]),
    }
    plaintext = json.dumps(plaintext_dict).encode("utf-8")

    # Chunking payloads due to 512-bit RSA restrictions
    chunk_size = 20
    chunks = [
        plaintext[i : i + chunk_size]
        for i in range(0, len(plaintext), chunk_size)
    ]

    # Package cipher implementation execution
    ciphertext_chunks = [
        base64.b64encode(cipher.encrypt(c)).decode("utf-8") for c in chunks
    ]

    # Map remaining metadata directly from CSV tracking positions
    vault_txns.append(
        {
            "txn_id": f"TXN-PAYSIM-{idx:05d}",
            "step": int(row["step"]),
            "type": str(row["type"]),
            "payload_encrypted": ciphertext_chunks,
            "isFlaggedFraud": int(row["isFraud"]),  # maps directly to your target field
            "risk_level": "HIGH" if int(row["isFraud"]) == 1 else "LOW",
        }
    )

# ---- 4. Save Final Vault Document ----
vault = {
    "vault_metadata": {
        "encryption": "RSA-512",
        "key_id": "VAULT-KEY-LEGACY-001",
        "rsa_public_key_pem": public_key.export_key().decode("utf-8"),
        "rsa_private_key_pem_DO_NOT_SHARE": key.export_key().decode("utf-8"),
        "institution": "MNB Singapore - Core Banking",
        "source_schema": "PaySim Parsed Production Vault Data",
    },
    "transactions": vault_txns,
}

with open("bank_vault.json", "w") as f:
    json.dump(vault, f, indent=2)

print(f"[+] Wrote bank_vault.json with {len(vault_txns)} records.")