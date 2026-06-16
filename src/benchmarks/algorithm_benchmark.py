"""
Performance comparison for classical RSA and post-quantum payment primitives.

When liboqs is installed, ML-KEM/ML-DSA/HQC/SLH-DSA use real OQS bindings.
Otherwise the code runs deterministic simulation workloads so the UI and
scoring workflow remain usable in classroom/demo environments.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import statistics
import time
from dataclasses import dataclass
from typing import Callable

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    hashes = serialization = padding = rsa = AESGCM = None
    CRYPTOGRAPHY_AVAILABLE = False

from algorithms.crypto_algorithms import ALGORITHM_PROFILES

try:
    import oqs  # type: ignore

    OQS_AVAILABLE = True
except ImportError:
    oqs = None
    OQS_AVAILABLE = False


PAYMENT_PAYLOAD = (
    b'{"txn_id":"TXN-BENCH-0001","type":"SWIFT_MT103","amount_sgd":2850000,'
    b'"sender":"DBSSSGSG","receiver":"NWBKGB2L","reference":"INV-MCP-2024-0091"}'
)


@dataclass
class BenchmarkResult:
    algorithm: str
    primitive: str
    implementation: str
    avg_ms: float
    p95_ms: float
    security_score: int
    quantum_safe: bool
    notes: str


def _measure(operation: Callable[[], None], iterations: int) -> tuple[float, float]:
    durations: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        durations.append((time.perf_counter() - start) * 1000)

    if len(durations) == 1:
        return durations[0], durations[0]
    sorted_durations = sorted(durations)
    p95_index = min(len(sorted_durations) - 1, int(len(sorted_durations) * 0.95))
    return statistics.mean(durations), sorted_durations[p95_index]


def _rsa_payment_operation() -> None:
    if not CRYPTOGRAPHY_AVAILABLE:
        _simulated_signature_operation(b"RSA-2048", rounds=160)
        _simulated_kem_operation(b"RSA-2048")
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    encrypted_payload = AESGCM(aes_key).encrypt(nonce, PAYMENT_PAYLOAD, None)
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    signature = private_key.sign(
        encrypted_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    public_key.verify(
        signature,
        encrypted_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _oqs_kem_operation(algorithm_names: list[str]) -> Callable[[], None] | None:
    if not OQS_AVAILABLE:
        return None
    for algorithm_name in algorithm_names:
        try:
            kem = oqs.KeyEncapsulation(algorithm_name)
            kem.free()
        except Exception:
            continue

        def operation(name: str = algorithm_name) -> None:
            with oqs.KeyEncapsulation(name) as kem:
                public_key = kem.generate_keypair()
                ciphertext, shared_secret = kem.encap_secret(public_key)
                kem.decap_secret(ciphertext)
                AESGCM(shared_secret[:32]).encrypt(os.urandom(12), PAYMENT_PAYLOAD, None)

        return operation
    return None


def _oqs_signature_operation(algorithm_names: list[str]) -> Callable[[], None] | None:
    if not OQS_AVAILABLE:
        return None
    for algorithm_name in algorithm_names:
        try:
            signature = oqs.Signature(algorithm_name)
            signature.free()
        except Exception:
            continue

        def operation(name: str = algorithm_name) -> None:
            with oqs.Signature(name) as signer:
                public_key = signer.generate_keypair()
                signed = signer.sign(PAYMENT_PAYLOAD)
                signer.verify(PAYMENT_PAYLOAD, signed, public_key)

        return operation
    return None


def _simulated_kem_operation(label: bytes) -> None:
    seed = os.urandom(32)
    public_key = hashlib.sha3_256(label + seed).digest()
    ciphertext = hashlib.shake_256(public_key + os.urandom(32)).digest(1088)
    shared_secret = hashlib.sha3_256(ciphertext + public_key).digest()
    if CRYPTOGRAPHY_AVAILABLE:
        AESGCM(shared_secret).encrypt(os.urandom(12), PAYMENT_PAYLOAD, None)
    else:
        hmac.new(shared_secret, PAYMENT_PAYLOAD + os.urandom(12), hashlib.sha3_256).digest()


def _simulated_signature_operation(label: bytes, rounds: int) -> None:
    secret = os.urandom(32)
    digest = PAYMENT_PAYLOAD
    for index in range(rounds):
        digest = hmac.new(secret, digest + label + index.to_bytes(2, "big"), hashlib.sha3_256).digest()
    hmac.compare_digest(digest, hmac.new(secret, PAYMENT_PAYLOAD + label, hashlib.sha3_256).digest())


def benchmark_algorithms(iterations: int = 5) -> list[BenchmarkResult]:
    iterations = max(1, iterations)
    candidates: list[tuple[str, str, str, Callable[[], None], str]] = [
        (
            "RSA-2048",
            "Encryption + signature",
            "cryptography real RSA" if CRYPTOGRAPHY_AVAILABLE else "simulation fallback",
            _rsa_payment_operation,
            "Legacy baseline: real RSA-OAEP key wrap, AES-GCM payload encryption, RSA-PSS signature.",
        )
    ]

    ml_kem_operation = _oqs_kem_operation(["ML-KEM-768", "Kyber768"]) or (
        lambda: _simulated_kem_operation(b"ML-KEM-768")
    )
    candidates.append(
        (
            "ML-KEM-768",
            "KEM + AEAD encryption",
            "liboqs" if OQS_AVAILABLE else "simulation fallback",
            ml_kem_operation,
            "Primary PQC encryption/KEM path for protecting payment data keys.",
        )
    )

    ml_dsa_operation = _oqs_signature_operation(["ML-DSA-65", "Dilithium3"]) or (
        lambda: _simulated_signature_operation(b"ML-DSA-65", rounds=48)
    )
    candidates.append(
        (
            "ML-DSA-65",
            "Digital signature",
            "liboqs" if OQS_AVAILABLE else "simulation fallback",
            ml_dsa_operation,
            "Primary PQC transaction authorization signature.",
        )
    )

    slh_dsa_operation = _oqs_signature_operation(["SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple"]) or (
        lambda: _simulated_signature_operation(b"SLH-DSA-128s", rounds=96)
    )
    candidates.append(
        (
            "SLH-DSA-128s",
            "Digital signature",
            "liboqs" if OQS_AVAILABLE else "simulation fallback",
            slh_dsa_operation,
            "Hash-based backup signature; useful for crypto-agility, usually heavier.",
        )
    )

    hqc_operation = _oqs_kem_operation(["HQC-128"]) or (
        lambda: _simulated_kem_operation(b"HQC-128")
    )
    candidates.append(
        (
            "HQC-128",
            "KEM + AEAD encryption",
            "liboqs" if OQS_AVAILABLE else "simulation fallback",
            hqc_operation,
            "Code-based backup KEM candidate with different assumptions from ML-KEM.",
        )
    )

    results: list[BenchmarkResult] = []
    for name, primitive, implementation, operation, notes in candidates:
        avg_ms, p95_ms = _measure(operation, iterations)
        profile = ALGORITHM_PROFILES[name]
        results.append(
            BenchmarkResult(
                algorithm=name,
                primitive=primitive,
                implementation=implementation,
                avg_ms=round(avg_ms, 3),
                p95_ms=round(p95_ms, 3),
                security_score=profile.base_score,
                quantum_safe=profile.quantum_safe,
                notes=notes,
            )
        )
    return results


def benchmark_results_as_dicts(iterations: int = 5) -> list[dict[str, object]]:
    return [result.__dict__ for result in benchmark_algorithms(iterations)]


def export_demo_public_key() -> str:
    """Expose a real RSA public key for demos that need sample key material."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return "cryptography is not installed; RSA public key export is unavailable."

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
