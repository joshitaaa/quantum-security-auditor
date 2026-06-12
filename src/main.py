"""
AQCA Hybrid Orchestration Loop
Threat detection → Quantum Audit → PQC Defense
"""

import json, sys
from pathlib import Path
from quantum_auditor import estimate_quantum_risk
from pqc_defense import defend_vault

VAULT_PATH = Path(__file__).parent.parent / "data" / "bank_vault.json"
OUTPUT_PATH = Path(__file__).parent.parent / "data" / "bank_vault_pqc_secured.json"

RISK_THRESHOLD = {"CRITICAL", "HIGH"}

def load_vault():
    with open(VAULT_PATH) as f:
        return json.load(f)

def display_banner():
    print("=" * 60)
    print("  AQCA — Automated Quantum Cryptographic Auditor v1.0")
    print("  Threat Framework: Shor's Algorithm / QFT Simulation")
    print("=" * 60)

def main():
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
        print(f"\n[⚠️  ALERT] {report['risk_score']} quantum threat detected!")
        print("[→] Routing to PQC Defense Module...\n")

        secured_vault = defend_vault(vault, report)

        with open(OUTPUT_PATH, "w") as f:
            json.dump(secured_vault, f, indent=2)

        print(f"\n[✅ DONE] Secured vault written to: {OUTPUT_PATH}")
    else:
        print("[OK] Risk within acceptable threshold. No PQC upgrade triggered.")

if __name__ == "__main__":
    main()