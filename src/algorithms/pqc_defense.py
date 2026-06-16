"""
PQC defense module for payment vault protection.

ML-KEM is used to establish a shared secret, then AES-256-GCM encrypts each
transaction payload. If liboqs is unavailable, the module uses a clearly marked
simulation fallback so the project remains runnable in demo environments.
"""

import json, os, hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Try real ML-KEM/Kyber (requires liboqs); fall back to AES-256 simulation.
try:
    import oqs
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False


def kyber_keygen():
    if KYBER_AVAILABLE:
        kem_name = "ML-KEM-768"
        try:
            kem = oqs.KeyEncapsulation(kem_name)
        except Exception:
            kem_name = "Kyber768"
            kem = oqs.KeyEncapsulation(kem_name)
        public_key = kem.generate_keypair()
        return kem, public_key
    else:
        # Simulate: generate a 32-byte secret as stand-in for Kyber shared secret
        sk = os.urandom(32)
        pk = hashlib.sha3_256(sk).digest()  # mock public key
        return sk, pk


def kyber_encapsulate(public_key):
    if KYBER_AVAILABLE:
        kem_enc = oqs.KeyEncapsulation("Kyber768")
        ciphertext, shared_secret = kem_enc.encap_secret(public_key)
        return ciphertext, shared_secret
    else:
        # Fallback: HKDF-derived shared secret
        salt = os.urandom(16)
        shared_secret = HKDF(
            algorithm=hashes.SHA3_256(), length=32, salt=salt, info=b"AQCA-PQC-Demo"
        ).derive(public_key)
        return salt, shared_secret  # salt acts as "ciphertext"


def pqc_encrypt_transaction(txn: dict, shared_secret: bytes) -> dict:
    """Re-encrypts a transaction payload using AES-256-GCM keyed from Kyber shared secret."""
    plaintext = json.dumps(txn).encode()
    nonce = os.urandom(12)
    aesgcm = AESGCM(shared_secret)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "txn_id":     txn["txn_id"],
        "algorithm":  "ML-KEM-768 + AES-256-GCM" if KYBER_AVAILABLE else "Simulated-ML-KEM-768 + AES-256-GCM",
        "nonce_hex":  nonce.hex(),
        "cipher_hex": ciphertext.hex(),
        "pqc_status": "PROTECTED"
    }


def defend_vault(vault: dict, risk_report: dict) -> dict:
    """Full vault re-encryption pipeline."""
    print(f"\n[PQC] Initiating post-quantum re-encryption...")
    print(f"[PQC] Using {'liboqs ML-KEM-768' if KYBER_AVAILABLE else 'Simulated ML-KEM-768 (AES fallback)'}")

    kem_obj, public_key = kyber_keygen()
    kt_obj, shared_secret = kyber_encapsulate(public_key)

    secured_txns = []
    for txn in vault["transactions"]:
        secured = pqc_encrypt_transaction(txn, shared_secret)
        secured_txns.append(secured)
        print(f"[PQC] ✅ {txn['txn_id']} → re-encrypted with {secured['algorithm']}")

    return {
        "vault_metadata": {**vault["vault_metadata"],
                           "encryption": "ML-KEM-768 + AES-256-GCM",
                           "pqc_upgrade_timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z",
                           "triggered_by_risk": risk_report["risk_score"]},
        "transactions": secured_txns
    }
