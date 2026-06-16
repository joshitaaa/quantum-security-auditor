# Quantum Security Auditor

Quantum Security Auditor evaluates payment transaction cryptography and demonstrates a migration path from legacy RSA to post-quantum cryptography (PQC).

The business scenario is payment transaction protection: encrypted payment payloads are scored for quantum-readiness, ciphertext quality, and business exposure.

## Implemented Algorithms

| Algorithm | Role | Status | Project use |
| --- | --- | --- | --- |
| RSA-2048 | Classical encryption/signature baseline | Legacy classical | Performance and security comparison baseline |
| ML-KEM-768 | Key encapsulation for encryption | NIST FIPS 203 | Primary PQC option for protecting payment data keys |
| ML-DSA-65 | Digital signature | NIST FIPS 204 | Primary PQC option for transaction authorization |
| SLH-DSA-128s | Hash-based digital signature | NIST FIPS 205 | Recommended backup signature family |
| HQC-128 | Code-based KEM | NIST selected in 2025 for future standardization | Recommended backup KEM family for crypto-agility |

ML-KEM and ML-DSA are the main algorithms requested for integration. SLH-DSA and HQC are included as recommended comparison algorithms because payment systems need backup families with different mathematical assumptions.

## Setup

```bash
pip install -r requirements.txt
```

Optional real PQC support:

```bash
pip install liboqs-python
```

If `liboqs-python` is not installed, PQC benchmark operations run in simulation fallback mode. RSA operations use real `cryptography` primitives.

## Run the Vault Auditor

```bash
python src/main.py
```

Default flow:

1. Loads `data/bank_vault.json`.
2. Runs the Shor/QFT quantum risk simulation for the legacy RSA vault.
3. Re-encrypts vault transactions with ML-KEM-derived AES-256-GCM protection when risk is high.
4. Writes `data/bank_vault_pqc_secured.json`.

## Compare Algorithms

```bash
python src/main.py --compare --iterations 5
```

The comparison prints local average and p95 operation time, security score, and quantum-safe status for RSA, ML-KEM, ML-DSA, SLH-DSA, and HQC.

Important interpretation: ML-KEM is a KEM/encryption primitive, while ML-DSA and SLH-DSA are signature primitives. They should not be treated as direct drop-in substitutes for each other. A payment deployment should normally use ML-KEM-768 for encrypting transaction data keys and ML-DSA-65 for authorization signatures.

## Score an Encrypted Payment

```bash
python src/main.py \
  --score-transaction "BASE64_OR_HEX_CIPHERTEXT" \
  --algorithm ML-KEM-768 \
  --amount-sgd 250000 \
  --channel SWIFT_MT103
```

## Run the Payment UI

```bash
streamlit run src/score_payment_tx_ui.py
```

The UI lets a business user:

- Select the payment channel and cryptographic algorithm.
- Paste an encrypted transaction payload.
- Enter the payment amount.
- Receive a 0-100 security score, risk rating, findings, and recommendation.
- View the algorithm scorecard and run local benchmarks.

## Run the Notebooks

Notebook versions are included for direct, visual output inspection:

```bash
jupyter notebook src/score_payment_tx_ui.ipynb
jupyter notebook src/algorithm_benchmark.ipynb
```

Use `src/score_payment_tx_ui.ipynb` to score sample encrypted payment transactions and compare business scenarios. Use `src/algorithm_benchmark.ipynb` to display the algorithm scorecard and local benchmark table.

## Security Score Logic

The score is deterministic and explainable:

- Base algorithm posture: RSA-2048 starts at 46, ML-KEM-768 at 93, ML-DSA-65 at 91, SLH-DSA-128s at 84, and HQC-128 at 82.
- Quantum safety: RSA receives an additional penalty because Shor's algorithm threatens integer-factorization cryptography.
- Ciphertext hygiene: empty, very short, invalid base64/hex, or low-entropy payloads lose points.
- Business exposure: high-value payments and cross-border channels receive additional risk penalties when not quantum-safe.

Risk rating:

| Score | Rating |
| --- | --- |
| 85-100 | LOW |
| 70-84 | MEDIUM |
| 50-69 | HIGH |
| 0-49 | CRITICAL |

## Example Comparison Result

Local timings vary by machine and by whether `liboqs-python` is installed. Expected security posture:

| Algorithm | Expected security score | Payment recommendation |
| --- | ---: | --- |
| RSA-2048 | 46 | Migrate away for long-lived payment confidentiality |
| ML-KEM-768 | 93 | Use for PQC key establishment and payload encryption |
| ML-DSA-65 | 91 | Use for PQC transaction signatures |
| SLH-DSA-128s | 84 | Keep as conservative backup signature family |
| HQC-128 | 82 | Track as backup KEM for crypto-agility |

## Key Files

- `src/main.py`: CLI orchestration for audit, comparison, and transaction scoring.
- `src/quantum_auditor.py`: Shor/QFT simulation and RSA quantum risk estimate.
- `src/pqc_defense.py`: ML-KEM plus AES-256-GCM vault re-encryption.
- `src/crypto_algorithms.py`: algorithm catalog and transaction scoring logic.
- `src/algorithm_benchmark.py`: RSA/PQC benchmark harness.
- `src/score_payment_tx_ui.py`: Streamlit UI for payment transaction scoring.
- `src/score_payment_tx_ui.ipynb`: Notebook for visual payment transaction scoring.
- `src/algorithm_benchmark.ipynb`: Notebook for visual benchmark and scorecard output.

## Future Improvements

- Replace simulation fallbacks with validated `liboqs` deployments in all environments.
- Add hybrid TLS-style workflows, for example X25519 plus ML-KEM-768 during migration.
- Add ML-DSA signature verification over full transaction authorization messages.
- Store benchmark history by hardware profile and compare p99 latency against payment SLA targets.
- Add fraud model signals separately from cryptographic risk so operational fraud and quantum-readiness are not mixed.
- Add key lifecycle controls: rotation dates, HSM/KMS integration, certificate inventory, and crypto-agility policy checks.
- Add authenticated batch scoring for uploaded payment files.
