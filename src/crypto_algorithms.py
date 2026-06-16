"""
Algorithm catalog, security scoring, and payment transaction risk helpers.

The scores are intentionally transparent and deterministic so business users can
explain why a transaction is considered quantum-safe or legacy-risky.
"""

from __future__ import annotations

import base64
import binascii
import math
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    family: str
    primary_use: str
    nist_status: str
    quantum_safe: bool
    production_role: str
    security_level: str
    strengths: str
    limitations: str
    base_score: int


ALGORITHM_PROFILES: dict[str, AlgorithmProfile] = {
    "RSA-2048": AlgorithmProfile(
        name="RSA-2048",
        family="Integer factorization",
        primary_use="Encryption/signature",
        nist_status="Classical legacy",
        quantum_safe=False,
        production_role="Legacy baseline for comparison",
        security_level="Classical ~112-bit; vulnerable to Shor's algorithm",
        strengths="Mature, widely supported, simple interoperability.",
        limitations="Not quantum-safe; large CPU cost for key operations.",
        base_score=46,
    ),
    "ML-KEM-768": AlgorithmProfile(
        name="ML-KEM-768",
        family="Module lattice",
        primary_use="Key encapsulation/encryption",
        nist_status="FIPS 203",
        quantum_safe=True,
        production_role="Primary PQC encryption/KEM choice",
        security_level="NIST category 3",
        strengths="Fast key establishment and compact PQC key material.",
        limitations="Protects key exchange; pair with AEAD and signatures.",
        base_score=93,
    ),
    "ML-DSA-65": AlgorithmProfile(
        name="ML-DSA-65",
        family="Module lattice",
        primary_use="Digital signature",
        nist_status="FIPS 204",
        quantum_safe=True,
        production_role="Primary PQC signature choice",
        security_level="NIST category 3",
        strengths="Strong standardized signature option for authorization.",
        limitations="Signing can have variable latency from rejection sampling.",
        base_score=91,
    ),
    "SLH-DSA-128s": AlgorithmProfile(
        name="SLH-DSA-128s",
        family="Hash based",
        primary_use="Digital signature",
        nist_status="FIPS 205",
        quantum_safe=True,
        production_role="Conservative backup signature option",
        security_level="NIST category 1",
        strengths="Security relies mostly on hash functions and mature assumptions.",
        limitations="Larger signatures and slower operations than ML-DSA.",
        base_score=84,
    ),
    "HQC-128": AlgorithmProfile(
        name="HQC-128",
        family="Code based",
        primary_use="Key encapsulation/encryption",
        nist_status="Selected by NIST in 2025 for future standardization",
        quantum_safe=True,
        production_role="Backup KEM for crypto-agility",
        security_level="NIST category 1 target",
        strengths="Different mathematical foundation than ML-KEM.",
        limitations="Not as deployment-ready as finalized FIPS 203 ML-KEM.",
        base_score=82,
    ),
}


def list_algorithm_profiles() -> list[dict[str, Any]]:
    return [asdict(profile) for profile in ALGORITHM_PROFILES.values()]


def get_algorithm_profile(name: str) -> AlgorithmProfile:
    return ALGORITHM_PROFILES.get(name, ALGORITHM_PROFILES["RSA-2048"])


def _is_probably_base64(value: str) -> bool:
    try:
        base64.b64decode(value, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _is_probably_hex(value: str) -> bool:
    if len(value) < 16 or len(value) % 2:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def score_encrypted_transaction(
    encrypted_payload: str,
    algorithm_name: str,
    amount_sgd: float = 0.0,
    channel: str = "PAYMENT",
) -> dict[str, Any]:
    """
    Score an encrypted payment payload for quantum migration risk.

    This is not fraud detection. It combines cryptographic posture, ciphertext
    hygiene, and payment exposure into a business-facing security score.
    """
    profile = get_algorithm_profile(algorithm_name)
    score = float(profile.base_score)
    findings: list[str] = []

    normalized_payload = encrypted_payload.strip()
    entropy = _shannon_entropy(normalized_payload)
    valid_encoding = _is_probably_base64(normalized_payload) or _is_probably_hex(normalized_payload)

    if not normalized_payload:
        score -= 35
        findings.append("Encrypted payload is empty.")
    elif len(normalized_payload) < 64:
        score -= 15
        findings.append("Ciphertext is unusually short for a protected payment record.")

    if not valid_encoding:
        score -= 10
        findings.append("Payload is not valid base64 or hex ciphertext.")

    if entropy < 4.0 and normalized_payload:
        score -= 10
        findings.append("Ciphertext entropy is low; verify that the payload is encrypted.")

    if "RSA" in profile.name:
        score -= 20
        findings.append("RSA is vulnerable to future cryptographically relevant quantum computers.")

    if amount_sgd >= 1_000_000:
        score -= 8
        findings.append("High-value payment increases harvest-now-decrypt-later exposure.")
    elif amount_sgd >= 100_000:
        score -= 4
        findings.append("Medium/high-value payment should use PQC or hybrid protection.")

    if channel.upper() in {"SWIFT", "SWIFT_MT103", "WIRE"} and not profile.quantum_safe:
        score -= 7
        findings.append("Cross-border payment channel should be prioritized for PQC migration.")

    bounded_score = max(0, min(100, round(score)))
    if bounded_score >= 85:
        rating = "LOW"
    elif bounded_score >= 70:
        rating = "MEDIUM"
    elif bounded_score >= 50:
        rating = "HIGH"
    else:
        rating = "CRITICAL"

    if not findings:
        findings.append("No major ciphertext or algorithm posture issues detected.")

    return {
        "algorithm": profile.name,
        "score": bounded_score,
        "risk_rating": rating,
        "quantum_safe": profile.quantum_safe,
        "entropy": round(entropy, 2),
        "valid_encoding": valid_encoding,
        "findings": findings,
        "recommendation": recommend_algorithm(profile.name),
    }


def recommend_algorithm(current_algorithm: str) -> str:
    if current_algorithm.startswith("RSA"):
        return "Migrate payment encryption to hybrid RSA/ECDHE + ML-KEM-768, then move to ML-KEM-only once approved."
    if current_algorithm.startswith("ML-KEM"):
        return "Keep ML-KEM-768 for key establishment and add ML-DSA-65 for transaction authorization signatures."
    if current_algorithm.startswith("ML-DSA"):
        return "Use ML-DSA-65 for signatures and ML-KEM-768 for encrypting transaction payload keys."
    if current_algorithm.startswith("SLH-DSA"):
        return "Use as a conservative backup signature option when larger signatures are acceptable."
    if current_algorithm.startswith("HQC"):
        return "Track HQC as a backup KEM for crypto-agility; keep ML-KEM-768 as the primary deployment choice."
    return "Review algorithm selection and prefer standardized PQC primitives for long-lived payment data."
