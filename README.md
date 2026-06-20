# Quantum Security Auditor

Quantum Security Auditor evaluates payment transaction cryptography and demonstrates a migration path from legacy RSA to post-quantum cryptography (PQC).

The business scenario is payment transaction protection: encrypted payment payloads are scored for quantum-readiness, ciphertext quality, and business exposure.

## Implemented Algorithms

| Algorithm    | Role                                    | Status                                           | Project use                                         |
| ------------ | --------------------------------------- | ------------------------------------------------ | --------------------------------------------------- |
| RSA-2048     | Classical encryption/signature baseline | Legacy classical                                 | Performance and security comparison baseline        |
| ML-KEM-768   | Key encapsulation for encryption        | NIST FIPS 203                                    | Primary PQC option for protecting payment data keys |
| ML-DSA-65    | Digital signature                       | NIST FIPS 204                                    | Primary PQC option for transaction authorization    |
| SLH-DSA-128s | Hash-based digital signature            | NIST FIPS 205                                    | Recommended backup signature family                 |
| HQC-128      | Code-based KEM                          | NIST selected in 2025 for future standardization | Recommended backup KEM family for crypto-agility    |

ML-KEM and ML-DSA are the main algorithms requested for integration. SLH-DSA and HQC are included as recommended comparison algorithms because payment systems need backup families with different mathematical assumptions.

## Setup and Run Notebooks

```bash
python -m pip install -e .
```

Optional real PQC support:

```bash
python -m pip install -e ".[pqc]"
```

If the editable install is not needed, the legacy requirements file is still available:

```bash
python -m pip install -r requirements.txt
```

`cryptography` is used for real RSA/AES operations. `liboqs-python` is optional; when it or a specific OQS algorithm is unavailable, the PQC benchmark uses a clearly marked `simulation fallback` implementation.

After setup, open and run these notebooks directly in VS Code:

- `src/score_payment_tx_ui.ipynb`: interactive Score Payment form for encrypted payment transaction scoring.
- `src/algorithm_benchmark.ipynb`: algorithm scorecard, local benchmark table, toy crack demo, and attack-time estimate.

In VS Code, select the Python environment where the setup command was run as the notebook kernel.

You can also launch the notebooks from a browser:

```bash
jupyter notebook src/score_payment_tx_ui.ipynb
jupyter notebook src/algorithm_benchmark.ipynb
```

To access the Score Payment notebook as a Chrome-friendly web page, run it with Voilà:

```bash
voila src/score_payment_tx_ui.ipynb --port 8866 --Voila.ip=127.0.0.1
```

Then open this URL in Chrome:

```text
http://localhost:8866
```

## Run the Vault Auditor

```bash
cd src
python -m cli.auditor_cli
```

Default flow:

1. Loads `data/bank_vault.json`.
2. Runs the Shor/QFT quantum risk simulation for the legacy RSA vault.
3. Re-encrypts vault transactions with ML-KEM-derived AES-256-GCM protection when risk is high.
4. Writes `data/bank_vault_pqc_secured.json`.

## Compare Algorithms

```bash
cd src
python -m cli.auditor_cli --compare --iterations 5
```

The comparison prints local average and p95 operation time, posture score, attack-time score, toy-crack score, estimated attack time, and quantum-safe status for RSA, ML-KEM, ML-DSA, SLH-DSA, and HQC.

Important interpretation: ML-KEM is a KEM/encryption primitive, while ML-DSA and SLH-DSA are signature primitives. They should not be treated as direct drop-in substitutes for each other. A payment deployment should normally use ML-KEM-768 for encrypting transaction data keys and ML-DSA-65 for authorization signatures.

The CLI and benchmark notebook include two crack-time views:

- `toy_crack_score`: actual brute-force time against intentionally tiny demo key spaces using the same transaction payload for every algorithm label.
- `attack_time_score`: estimated classical/quantum attack years from brute-force-equivalent security strength and local trial-rate calibration.

The toy crack is real, but it is only a bounded classroom demonstration. It is not a real crack of standardized RSA-2048, ML-KEM, ML-DSA, SLH-DSA, or HQC parameters.

## Score an Encrypted Payment

```bash
cd src
python -m cli.auditor_cli \
  --score-transaction "BASE64_OR_HEX_CIPHERTEXT" \
  --algorithm ML-KEM-768 \
  --amount-sgd 250000 \
  --channel SWIFT_MT103
```

## Payment Security Scoring Logic

The project uses three related scores. They should be read together, not as a single cryptographic proof:

- `score`: the payment transaction score used by the CLI and Score Payment notebook.
- `security_score`: the base algorithm posture used in benchmark tables.
- `toy_crack_score` and `attack_time_score`: benchmark-only crack-time views.

Transaction score starts from the selected algorithm posture and applies business-facing penalties:

| Factor                          | Logic                                                                                                                                                                                                                                                              |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Base posture                    | RSA-2048 starts at 46, ML-KEM-768 at 93, ML-DSA-65 at 91, SLH-DSA-128s at 84, and HQC-128 at 82.                                                                                                                                                                   |
| Quantum safety                  | RSA loses 20 additional points because Shor's algorithm threatens integer-factorization cryptography.                                                                                                                                                              |
| Ciphertext hygiene              | Empty payloads lose 35 points, very short payloads lose 15, invalid base64/hex loses 10, and low entropy loses 10.                                                                                                                                                 |
| Payment exposure                | This reflects business exposure and attacker incentive for harvest-now-decrypt-later collection.<br />It does not mean the algorithm becomes easier to break.<br />Payments of SGD 100,000 or more lose 4 points; payments of SGD 1,000,000 or more lose 8 points. |
| Cross-border migration priority | This reflects the higher long-term sensitivity and migration priority of cross-border payment messages.<br />It does not mean the algorithm becomes easier to break.<br />Non-quantum-safe SWIFT/WIRE payments lose 7 additional points.                          |

Benchmark crack-time views:

| Score                 | Source                                                                                                                            | Purpose                                                                              |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `toy_crack_score`   | Actual brute-force time against intentionally tiny demo key spaces<br />using the same payment payload for every algorithm label. | Demonstrates how measured crack time changes as toy keyspace size changes.           |
| `attack_time_score` | Estimated classical/quantum attack years from<br />brute-force-equivalent security bits and local trial-rate calibration.         | Gives a more realistic security-strength view for standardized algorithm parameters. |

Risk rating:

| Score  | Rating   |
| ------ | -------- |
| 85-100 | LOW      |
| 70-84  | MEDIUM   |
| 50-69  | HIGH     |
| 0-49   | CRITICAL |

## Comparison Result

`iterations = 5` is a reasonable default for this project. It smooths single-run timing noise while keeping the benchmark fast enough for notebooks and classroom demos. Local timings vary by machine and by whether `liboqs-python` is installed. The example below was measured on this workspace using simulation fallback for PQC operations.

Operation benchmark:

| Algorithm    | Impl                | Avg ms | P95 ms | Posture score | Attack-time score | PQ-safe |
| ------------ | ------------------- | -----: | -----: | ------------: | ----------------: | ------- |
| RSA-2048     | simulation fallback |  0.623 |  1.068 |            46 |                35 | No      |
| ML-KEM-768   | simulation fallback |  0.014 |  0.026 |            93 |               100 | Yes     |
| ML-DSA-65    | simulation fallback |  0.185 |  0.251 |            91 |               100 | Yes     |
| SLH-DSA-128s | simulation fallback |  0.308 |  0.343 |            84 |                75 | Yes     |
| HQC-128      | simulation fallback |  0.015 |  0.027 |            82 |                75 | Yes     |

Toy crack demo:

| Algorithm    | Toy key bits | Toy keyspace | Crack ms | Toy crack score |
| ------------ | -----------: | -----------: | -------: | --------------: |
| RSA-2048     |           12 |        4,096 |   11.009 |              25 |
| HQC-128      |           14 |       16,384 |   27.977 |              45 |
| SLH-DSA-128s |           14 |       16,384 |   48.930 |              45 |
| ML-KEM-768   |           15 |       32,768 |   93.336 |              45 |
| ML-DSA-65    |           15 |       32,768 |   71.650 |              45 |

Attack-time estimate:

| Algorithm    | Estimated classical attack | Estimated quantum attack | Attack-time score |
| ------------ | -------------------------: | -----------------------: | ----------------: |
| RSA-2048     |              ~1e19.9 years |              10.00 years |                35 |
| ML-KEM-768   |              ~1e44.0 years |            ~1e24.7 years |               100 |
| ML-DSA-65    |              ~1e44.0 years |            ~1e24.7 years |               100 |
| SLH-DSA-128s |              ~1e24.7 years |             ~1e5.4 years |                75 |
| HQC-128      |              ~1e24.7 years |             ~1e5.4 years |                75 |

## Key Files

- `pyproject.toml`: package metadata, dependencies, and console script configuration.
- `src/cli/auditor_cli.py`: CLI orchestration for audit, comparison, and transaction scoring.
- `src/algorithms/crypto_algorithms.py`: algorithm catalog and transaction scoring logic.
- `src/algorithms/quantum_auditor.py`: Shor/QFT simulation and RSA quantum risk estimate.
- `src/algorithms/pqc_defense.py`: ML-KEM plus AES-256-GCM vault re-encryption.
- `src/benchmarks/algorithm_benchmark.py`: RSA/PQC benchmark harness.
- `src/ui/payment_security_web_app.py`: Streamlit web app for payment transaction scoring.
- `src/data_tools/generate_vault_data.py`: PaySim-to-vault generation logic.
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
