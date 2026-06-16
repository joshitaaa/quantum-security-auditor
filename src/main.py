"""
AQCA Hybrid Orchestration Loop
Threat detection -> Quantum Audit -> PQC Defense -> Payment scoring
"""

import argparse
import json
from pathlib import Path
from crypto_algorithms import ALGORITHM_PROFILES, score_encrypted_transaction

VAULT_PATH = Path(__file__).parent.parent / "data" / "bank_vault.json"
OUTPUT_PATH = Path(__file__).parent.parent / "data" / "bank_vault_pqc_secured.json"

RISK_THRESHOLD = {"CRITICAL", "HIGH"}

def load_vault():
    with open(VAULT_PATH) as f:
        return json.load(f)

def display_banner():
    print("=" * 60)
    print("  AQCA - Automated Quantum Cryptographic Auditor v1.1")
    print("  Threat Framework: Shor's Algorithm / QFT Simulation")
    print("=" * 60)


def print_algorithm_comparison(iterations: int = 5):
    from algorithm_benchmark import benchmark_algorithms

    print("\n[COMPARE] Payment security algorithm benchmark")
    print("[COMPARE] Primitive types differ: KEM/encryption protects payload keys; signatures authorize transactions.\n")
    header = f"{'Algorithm':<15} {'Primitive':<26} {'Impl':<22} {'Avg ms':>8} {'P95 ms':>8} {'Score':>7} {'PQ-safe':>8}"
    print(header)
    print("-" * len(header))
    for result in benchmark_algorithms(iterations=iterations):
        print(
            f"{result.algorithm:<15} {result.primitive:<26} {result.implementation:<22} "
            f"{result.avg_ms:>8.3f} {result.p95_ms:>8.3f} {result.security_score:>7} {str(result.quantum_safe):>8}"
        )
    print("\n[COMPARE] Recommended deployment profile: ML-KEM-768 for encrypted payment keys + ML-DSA-65 for authorization signatures.")
    print("[COMPARE] Add SLH-DSA and HQC to the roadmap as backup families for crypto-agility.\n")


def print_transaction_score(payload: str, algorithm: str, amount_sgd: float, channel: str):
    result = score_encrypted_transaction(payload, algorithm, amount_sgd, channel)
    print("\n[PAYMENT SCORE]")
    print(f"Algorithm       : {result['algorithm']}")
    print(f"Security Score  : {result['score']}/100")
    print(f"Risk Rating     : {result['risk_rating']}")
    print(f"Quantum Safe    : {result['quantum_safe']}")
    print(f"Cipher Entropy  : {result['entropy']}")
    print(f"Valid Encoding  : {result['valid_encoding']}")
    print("Findings:")
    for finding in result["findings"]:
        print(f"  - {finding}")
    print(f"Recommendation  : {result['recommendation']}\n")


def run_vault_audit():
    from pqc_defense import defend_vault
    from quantum_auditor import estimate_quantum_risk

    display_banner()

    vault = load_vault()
    key_bits = 512  # deliberately weak RSA key size in vault
    print(f"\n[AUDIT] Detected encryption: RSA-{key_bits}")
    print(f"[AUDIT] Running quantum threat simulation...\n")

    # Step 1: Quantum threat assessment
    report = estimate_quantum_risk(key_bits)

    print(f"[RESULT] Risk Score      : {report['risk_score']}")
    print(f"[RESULT] Logical Qubits  : {report['logical_qubits_real']:,}")
    print(f"[RESULT] Physical Qubits : {report['physical_qubits_real']:,} (surface code)")
    print(f"[RESULT] Projected Break : {report['projected_break_year']}")
    print(f"[RESULT] Gate Depth Real : {report['gate_depth_real']:,}")
    print(f"\n[SIM] Circuit Diagram (simplified):\n{report['circuit_diagram']}")
    print(f"\n[SIM] Measurement Outcomes: {report['sim_counts']}")

    # Step 2: Route to PQC defense if high risk
    if report["risk_score"] in RISK_THRESHOLD:
        print(f"\n[ALERT] {report['risk_score']} quantum threat detected!")
        print("[ROUTE] Routing to PQC Defense Module...\n")

        secured_vault = defend_vault(vault, report)

        with open(OUTPUT_PATH, "w") as f:
            json.dump(secured_vault, f, indent=2)

        print(f"\n[DONE] Secured vault written to: {OUTPUT_PATH}")
    else:
        print("[OK] Risk within acceptable threshold. No PQC upgrade triggered.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Quantum Security Auditor for payment transactions.")
    parser.add_argument("--compare", action="store_true", help="Benchmark and score RSA, ML-KEM, ML-DSA, SLH-DSA, and HQC.")
    parser.add_argument("--iterations", type=int, default=5, help="Benchmark iterations per algorithm.")
    parser.add_argument("--score-transaction", type=str, help="Encrypted payload to score from the command line.")
    parser.add_argument("--algorithm", choices=sorted(ALGORITHM_PROFILES), default="RSA-2048", help="Algorithm used for the encrypted payload.")
    parser.add_argument("--amount-sgd", type=float, default=0.0, help="Payment amount in SGD for exposure scoring.")
    parser.add_argument("--channel", type=str, default="PAYMENT", help="Payment channel, for example SWIFT_MT103, ACH_CREDIT, or CARD.")
    parser.add_argument("--skip-vault-audit", action="store_true", help="Do not run the original vault audit flow.")
    return parser


def main():
    args = build_parser().parse_args()

    if args.compare:
        print_algorithm_comparison(args.iterations)

    if args.score_transaction is not None:
        print_transaction_score(args.score_transaction, args.algorithm, args.amount_sgd, args.channel)

    if not args.compare and args.score_transaction is None and not args.skip_vault_audit:
        run_vault_audit()


if __name__ == "__main__":
    main()
