"""
Performance comparison for classical RSA and post-quantum payment primitives.

When liboqs is installed, ML-KEM/ML-DSA/HQC/SLH-DSA use real OQS bindings.
Otherwise the code runs deterministic simulation workloads so the UI and
scoring workflow remain usable in classroom/demo environments.
"""

from __future__ import annotations

import hashlib
import hmac
import math
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
    attack_time_score: int
    estimated_classical_attack_years: str
    estimated_quantum_attack_years: str
    attack_model: str
    quantum_safe: bool
    notes: str


@dataclass
class AttackEstimate:
    algorithm: str
    estimated_classical_attack_years: str
    estimated_quantum_attack_years: str
    attack_time_score: int
    attack_model: str


@dataclass
class ToyCrackResult:
    algorithm: str
    toy_key_bits: int
    toy_keyspace: int
    cracked_candidate: int
    crack_time_ms: float
    toy_crack_score: int
    notes: str


ATTACK_PROFILES = {
    "RSA-2048": {
        "classical_security_bits": 112,
        "quantum_security_bits": 0,
        "quantum_years": 10,
        "model": "RSA-2048 is classically hard, but Shor's algorithm makes it non-quantum-safe once CRQCs exist.",
    },
    "ML-KEM-768": {
        "classical_security_bits": 192,
        "quantum_security_bits": 128,
        "model": "NIST category 3 lattice KEM; estimate uses brute-force-equivalent security bits, not a practical lattice attack.",
    },
    "ML-DSA-65": {
        "classical_security_bits": 192,
        "quantum_security_bits": 128,
        "model": "NIST category 3 lattice signature; estimate uses brute-force-equivalent forgery resistance.",
    },
    "SLH-DSA-128s": {
        "classical_security_bits": 128,
        "quantum_security_bits": 64,
        "model": "Hash-based signature; quantum estimate reflects Grover-style square-root speedup for category 1 strength.",
    },
    "HQC-128": {
        "classical_security_bits": 128,
        "quantum_security_bits": 64,
        "model": "Code-based KEM candidate; estimate uses category 1 brute-force-equivalent attack resistance.",
    },
}

TOY_CRACK_BITS = {
    "RSA-2048": 12,
    "HQC-128": 14,
    "SLH-DSA-128s": 14,
    "ML-KEM-768": 15,
    "ML-DSA-65": 15,
}

_CALIBRATED_ATTEMPTS_PER_SECOND: float | None = None


def _calibrate_hash_attempts_per_second(duration_seconds: float = 0.05) -> float:
    """Calibrate a local trial rate with SHA-256 work units for attack-time estimates."""
    global _CALIBRATED_ATTEMPTS_PER_SECOND
    if _CALIBRATED_ATTEMPTS_PER_SECOND is not None:
        return _CALIBRATED_ATTEMPTS_PER_SECOND

    attempts = 0
    seed = os.urandom(16)
    deadline = time.perf_counter() + duration_seconds
    while time.perf_counter() < deadline:
        hashlib.sha256(seed + attempts.to_bytes(8, "big")).digest()
        attempts += 1
    _CALIBRATED_ATTEMPTS_PER_SECOND = max(1.0, attempts / duration_seconds)
    return _CALIBRATED_ATTEMPTS_PER_SECOND


def _format_years(years: float | None) -> str:
    if years is None:
        return "not quantum-safe"
    if years < 1:
        return f"{years * 365:.2f} days"
    if years < 1_000:
        return f"{years:.2f} years"
    return f"~1e{math.log10(years):.1f} years"


def _years_from_security_bits(security_bits: int, attempts_per_second: float) -> float:
    seconds_per_year = 365.25 * 24 * 60 * 60
    average_attempts = 2 ** max(0, security_bits - 1)
    return average_attempts / attempts_per_second / seconds_per_year


def _score_from_years(years: float | None, quantum_safe: bool) -> int:
    if years is None or not quantum_safe:
        return 35
    if years >= 1e20:
        return 100
    if years >= 1e12:
        return 95
    if years >= 1e6:
        return 88
    if years >= 100:
        return 75
    if years >= 10:
        return 60
    if years >= 1:
        return 45
    return 20


def _score_from_toy_crack_time(crack_time_ms: float) -> int:
    if crack_time_ms >= 2_000:
        return 100
    if crack_time_ms >= 1_000:
        return 90
    if crack_time_ms >= 500:
        return 80
    if crack_time_ms >= 100:
        return 65
    if crack_time_ms >= 25:
        return 45
    return 25


def estimate_attack_resistance(attempts_per_second: float | None = None) -> list[AttackEstimate]:
    """
    Estimate attack time from brute-force-equivalent security bits.

    This is intentionally an estimate, not a real crack of RSA/PQC keys. Real
    attacks on standardized parameters are infeasible in a local demo.
    """
    attempts_per_second = attempts_per_second or _calibrate_hash_attempts_per_second()
    estimates: list[AttackEstimate] = []

    for algorithm, profile in ATTACK_PROFILES.items():
        classical_years = _years_from_security_bits(profile["classical_security_bits"], attempts_per_second)
        quantum_bits = profile["quantum_security_bits"]
        quantum_years = None if quantum_bits <= 0 else _years_from_security_bits(quantum_bits, attempts_per_second)
        attack_score = _score_from_years(quantum_years, ALGORITHM_PROFILES[algorithm].quantum_safe)
        if algorithm == "RSA-2048":
            quantum_years = float(profile["quantum_years"])

        estimates.append(
            AttackEstimate(
                algorithm=algorithm,
                estimated_classical_attack_years=_format_years(classical_years),
                estimated_quantum_attack_years=_format_years(quantum_years),
                attack_time_score=attack_score,
                attack_model=f"{profile['model']} Local calibration: {attempts_per_second:,.0f} trial ops/sec.",
            )
        )

    return estimates


def attack_estimates_as_dicts() -> list[dict[str, object]]:
    return [estimate.__dict__ for estimate in estimate_attack_resistance()]


def run_toy_crack_demo(payload: bytes = PAYMENT_PAYLOAD) -> list[ToyCrackResult]:
    """
    Run an actual brute-force crack against intentionally tiny demo key spaces.

    This uses the same payment payload for every algorithm label, but it does
    not attack real RSA/PQC ciphertext. It is a bounded classroom calibration
    that demonstrates how crack time grows as security bits increase.
    """
    results: list[ToyCrackResult] = []

    for algorithm, toy_bits in TOY_CRACK_BITS.items():
        keyspace = 2 ** toy_bits
        target_candidate = int.from_bytes(hashlib.sha256(algorithm.encode("utf-8") + payload).digest()[:4], "big")
        target_candidate = keyspace // 2 + (target_candidate % max(1, keyspace // 2))
        target_digest = hmac.new(
            target_candidate.to_bytes(4, "big"),
            payload + algorithm.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        start = time.perf_counter()
        cracked_candidate = -1
        for candidate in range(keyspace):
            candidate_digest = hmac.new(
                candidate.to_bytes(4, "big"),
                payload + algorithm.encode("utf-8"),
                hashlib.sha256,
            ).digest()
            if hmac.compare_digest(candidate_digest, target_digest):
                cracked_candidate = candidate
                break
        crack_time_ms = (time.perf_counter() - start) * 1000

        results.append(
            ToyCrackResult(
                algorithm=algorithm,
                toy_key_bits=toy_bits,
                toy_keyspace=keyspace,
                cracked_candidate=cracked_candidate,
                crack_time_ms=round(crack_time_ms, 3),
                toy_crack_score=_score_from_toy_crack_time(crack_time_ms),
                notes="Actual brute-force crack of a tiny demo keyspace only; not a crack of real standardized parameters.",
            )
        )

    return results


def toy_crack_results_as_dicts() -> list[dict[str, object]]:
    return [result.__dict__ for result in run_toy_crack_demo()]


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
    attack_estimates = {estimate.algorithm: estimate for estimate in estimate_attack_resistance()}
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
        attack_estimate = attack_estimates[name]
        results.append(
            BenchmarkResult(
                algorithm=name,
                primitive=primitive,
                implementation=implementation,
                avg_ms=round(avg_ms, 3),
                p95_ms=round(p95_ms, 3),
                security_score=profile.base_score,
                attack_time_score=attack_estimate.attack_time_score,
                estimated_classical_attack_years=attack_estimate.estimated_classical_attack_years,
                estimated_quantum_attack_years=attack_estimate.estimated_quantum_attack_years,
                attack_model=attack_estimate.attack_model,
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
