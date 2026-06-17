from __future__ import annotations

import base64
import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def gen_weak_rsa_512():
    from Crypto.PublicKey import RSA
    from Crypto.Util import number

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


def generate_vault_data(
    csv_path: Path | str = PROJECT_ROOT / "data" / "paysim.csv",
    output_path: Path | str = PROJECT_ROOT / "data" / "bank_vault.json",
) -> dict:
    """Generate a weak RSA-512 demo vault from a PaySim-style CSV file."""
    import pandas as pd
    from Crypto.Cipher import PKCS1_OAEP

    df = pd.read_csv(csv_path)

    print("[*] Generating RSA-512 keypair (legacy bank key, unbalanced primes)...")
    key = gen_weak_rsa_512()
    public_key = key.publickey()
    cipher = PKCS1_OAEP.new(public_key)

    print(f"[*] Processing {len(df)} records from PaySim dataset...")
    vault_txns = []

    for idx, row in df.iterrows():
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

        # RSA-512 can only encrypt very small payloads, so the demo chunks records.
        chunk_size = 20
        chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
        ciphertext_chunks = [base64.b64encode(cipher.encrypt(c)).decode("utf-8") for c in chunks]

        vault_txns.append(
            {
                "txn_id": f"TXN-PAYSIM-{idx:05d}",
                "step": int(row["step"]),
                "type": str(row["type"]),
                "payload_encrypted": ciphertext_chunks,
                "isFlaggedFraud": int(row["isFraud"]),
                "risk_level": "HIGH" if int(row["isFraud"]) == 1 else "LOW",
            }
        )

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

    output_path = Path(output_path)
    with open(output_path, "w") as f:
        json.dump(vault, f, indent=2)

    print(f"[+] Wrote {output_path} with {len(vault_txns)} records.")
    return vault


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a demo payment vault from a PaySim-style CSV file.")
    parser.add_argument(
        "--csv-path",
        default=PROJECT_ROOT / "data" / "paysim.csv",
        type=Path,
        help="Input PaySim-style CSV path.",
    )
    parser.add_argument(
        "--output-path",
        default=PROJECT_ROOT / "data" / "bank_vault.json",
        type=Path,
        help="Output vault JSON path.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    generate_vault_data(args.csv_path, args.output_path)


if __name__ == "__main__":
    main()
