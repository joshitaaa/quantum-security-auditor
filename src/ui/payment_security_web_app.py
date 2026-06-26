"""
Interactive Streamlit web app for payment transaction security scoring.

Run with:
    streamlit run src/ui/payment_security_web_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import base64
import contextlib
import io
import json
import math
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from algorithms.crypto_algorithms import ALGORITHM_PROFILES, list_algorithm_profiles, score_encrypted_transaction
from algorithms.pqc_defense import defend_vault
from algorithms.quantum_auditor import estimate_quantum_risk, run_innovative_circuit_demo
from benchmarks.algorithm_benchmark import attack_estimates_as_dicts, benchmark_results_as_dicts, toy_crack_results_as_dicts


_RISK_COLORS = {"LOW": "#157347", "MEDIUM": "#997404", "HIGH": "#b54708", "CRITICAL": "#b42318"}

_DEMO_VAULT = {
    "vault_metadata": {"encryption": "RSA-512", "key_id": "VAULT-KEY-LEGACY-001",
                       "institution": "MNB Singapore - Core Banking (Demo)"},
    "transactions": [
        {"txn_id": "TXN-DEMO-00001", "type": "SWIFT_MT103", "amount": 2_850_000.0},
        {"txn_id": "TXN-DEMO-00002", "type": "ACH_CREDIT",  "amount": 450_000.0},
        {"txn_id": "TXN-DEMO-00003", "type": "WIRE",        "amount": 125_000.0},
    ],
}

SAMPLE_TRANSACTIONS: dict[str, dict[str, Any]] = {
    "Legacy high-value SWIFT": {
        "txn_id": "TXN-20240301-00192",
        "algorithm": "RSA-2048",
        "channel": "SWIFT_MT103",
        "amount_sgd": 2_850_000.0,
        "payload": base64.b64encode(b"legacy-rsa512-ciphertext-demo-payment-record").decode("utf-8"),
    },
    "PQC protected SWIFT": {
        "txn_id": "TXN-20240301-00988",
        "algorithm": "ML-KEM-768",
        "channel": "SWIFT_MT103",
        "amount_sgd": 2_850_000.0,
        "payload": (
            "f4a7c9e2b8d60144aa31f0dbe9368a22f10593d984bc6a73"
            "71ec0fb5346329af68a80bd8e8f7b908c9dbe6719041cfbc"
        ),
    },
    "Signed ACH authorization": {
        "txn_id": "TXN-20240301-00193",
        "algorithm": "ML-DSA-65",
        "channel": "ACH_CREDIT",
        "amount_sgd": 450_000.0,
        "payload": base64.b64encode(b"ml-dsa-signature-demo-for-ach-payment-authorization").decode("utf-8"),
    },
}


def configure_page() -> None:
    st.set_page_config(page_title="Quantum Payment Security Auditor", layout="wide")
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
        div[data-testid="stMetric"] {
            background: #f7f8fa;
            border: 1px solid #e4e7ec;
            border-radius: 8px;
            padding: 12px 14px;
        }
        div[data-testid="stMetric"] label,
        div[data-testid="stMetric"] div[data-testid="stMetricValue"],
        div[data-testid="stMetric"] div[data-testid="stMetricValue"] > div {
            color: #101828 !important;
        }
        .risk-low { color: #157347; font-weight: 700; }
        .risk-medium { color: #997404; font-weight: 700; }
        .risk-high { color: #b54708; font-weight: 700; }
        .risk-critical { color: #b42318; font-weight: 700; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def risk_class(risk_rating: str) -> str:
    return f"risk-{risk_rating.lower()}"


def result_to_row(label: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": label,
        "algorithm": result["algorithm"],
        "score": result["score"],
        "risk_rating": result["risk_rating"],
        "quantum_safe": result["quantum_safe"],
        "entropy": result["entropy"],
        "valid_encoding": result["valid_encoding"],
        "recommendation": result["recommendation"],
    }


def render_score_summary(result: dict[str, Any]) -> None:
    score_col, risk_col, quantum_col, encoding_col = st.columns(4)
    score_col.metric("Security score", f"{result['score']}/100")
    risk_col.metric("Risk rating", result["risk_rating"])
    quantum_col.metric("Quantum safe", "Yes" if result["quantum_safe"] else "No")
    encoding_col.metric("Valid encoding", "Yes" if result["valid_encoding"] else "No")

    st.markdown(
        f"<p class='{risk_class(result['risk_rating'])}'>Current risk: {result['risk_rating']}</p>",
        unsafe_allow_html=True,
    )
    st.progress(result["score"] / 100)

    st.write("Findings")
    for finding in result["findings"]:
        st.write(f"- {finding}")
    st.info(result["recommendation"])


def render_transaction_tab() -> None:
    st.subheader("Payment Transaction Scoring")

    selected_sample = st.selectbox("Load sample transaction", list(SAMPLE_TRANSACTIONS.keys()))
    sample = SAMPLE_TRANSACTIONS[selected_sample]

    with st.form("transaction_score_form"):
        left, right = st.columns([1, 1])
        with left:
            txn_id = st.text_input("Transaction ID", value=sample["txn_id"])
            algorithm = st.selectbox(
                "Encryption or signature algorithm",
                list(ALGORITHM_PROFILES.keys()),
                index=list(ALGORITHM_PROFILES.keys()).index(sample["algorithm"]),
            )
            channel = st.selectbox(
                "Payment channel",
                ["SWIFT_MT103", "ACH_CREDIT", "CARD", "WIRE", "PAYMENT"],
                index=["SWIFT_MT103", "ACH_CREDIT", "CARD", "WIRE", "PAYMENT"].index(sample["channel"]),
            )
            amount_sgd = st.number_input(
                "Payment amount (SGD)",
                min_value=0.0,
                value=float(sample["amount_sgd"]),
                step=1_000.0,
            )
        with right:
            encrypted_payload = st.text_area(
                "Encrypted transaction payload",
                value=sample["payload"],
                height=205,
                placeholder="Paste base64 or hex ciphertext here",
            )

        submitted = st.form_submit_button("Score Transaction", type="primary")

    if submitted or "latest_score" not in st.session_state:
        st.session_state["latest_score"] = {
            "txn_id": txn_id,
            "result": score_encrypted_transaction(encrypted_payload, algorithm, amount_sgd, channel),
            "payload": encrypted_payload,
            "amount_sgd": amount_sgd,
            "channel": channel,
        }

    latest = st.session_state["latest_score"]
    st.caption(f"Transaction: {latest['txn_id']} | Channel: {latest['channel']} | Amount: SGD {latest['amount_sgd']:,.2f}")
    render_score_summary(latest["result"])

    with st.expander("Raw score output"):
        st.json(latest["result"])


def render_scenario_tab() -> None:
    st.subheader("Scenario Comparison")
    rows = []
    for label, scenario in SAMPLE_TRANSACTIONS.items():
        result = score_encrypted_transaction(
            scenario["payload"],
            scenario["algorithm"],
            scenario["amount_sgd"],
            scenario["channel"],
        )
        rows.append(result_to_row(label, result))

    scenario_df = pd.DataFrame(rows)
    st.dataframe(
        scenario_df[
            [
                "label",
                "algorithm",
                "score",
                "risk_rating",
                "quantum_safe",
                "entropy",
                "valid_encoding",
                "recommendation",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.bar_chart(scenario_df.set_index("label")["score"])


def render_scorecard_tab() -> None:
    st.subheader("Algorithm Scorecard")
    profiles = pd.DataFrame(list_algorithm_profiles())
    st.dataframe(
        profiles[
            [
                "name",
                "family",
                "primary_use",
                "nist_status",
                "quantum_safe",
                "security_level",
                "base_score",
                "production_role",
                "limitations",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )


def render_benchmark_tab() -> None:
    st.subheader("Performance and Attack-Resistance Comparison")
    control_col, status_col = st.columns([1, 2])
    with control_col:
        iterations = st.slider("Benchmark iterations", min_value=1, max_value=20, value=5)
        run_benchmark = st.button("Run Benchmark", type="primary")
    with status_col:
        st.write(
            "Benchmark output uses real crypto libraries when available and simulation fallback otherwise. "
            "Toy crack results use intentionally tiny key spaces and are not real cracks of standardized parameters."
        )

    if run_benchmark or "benchmark_results" not in st.session_state:
        with st.spinner("Running local benchmark..."):
            st.session_state["benchmark_results"] = benchmark_results_as_dicts(iterations)
            st.session_state["toy_crack_results"] = toy_crack_results_as_dicts()
            st.session_state["attack_estimates"] = attack_estimates_as_dicts()

    benchmark_df = pd.DataFrame(st.session_state["benchmark_results"])
    st.write("Operation Benchmark and Security Scores")
    st.dataframe(benchmark_df, use_container_width=True, hide_index=True)
    st.bar_chart(benchmark_df.set_index("algorithm")["avg_ms"])

    toy_crack_df = pd.DataFrame(st.session_state["toy_crack_results"])
    st.write("Toy Crack Demo")
    st.dataframe(
        toy_crack_df[
            [
                "algorithm",
                "toy_key_bits",
                "toy_keyspace",
                "crack_time_ms",
                "toy_crack_score",
                "notes",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    attack_df = pd.DataFrame(st.session_state["attack_estimates"])
    st.write("Attack-Time Estimate")
    st.dataframe(
        attack_df[
            [
                "algorithm",
                "estimated_classical_attack_years",
                "estimated_quantum_attack_years",
                "attack_time_score",
                "attack_model",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )


def render_export_tab() -> None:
    st.subheader("Export Current Assessment")
    latest = st.session_state.get("latest_score")
    if not latest:
        st.write("Score a transaction first.")
        return

    export_payload = {
        "transaction_id": latest["txn_id"],
        "channel": latest["channel"],
        "amount_sgd": latest["amount_sgd"],
        "payload_preview": latest["payload"][:48],
        "score_result": latest["result"],
    }
    st.download_button(
        "Download Assessment JSON",
        data=json.dumps(export_payload, indent=2),
        file_name=f"{latest['txn_id']}_quantum_security_score.json",
        mime="application/json",
    )
    st.json(export_payload)


def render_quantum_tab() -> None:
    st.subheader("Quantum Threat Engine")

    # ── 1. Live Quantum Risk Analysis ──────────────────────────────────────
    st.markdown("### Quantum Risk Analysis")
    key_map = {
        "RSA-512  (CRITICAL — ~2026)": 512,
        "RSA-1024 (HIGH    — ~2029)": 1024,
        "RSA-2048 (MEDIUM  — ~2033)": 2048,
        "ECC-256  (proxy: RSA-512 quantum cost)": 512,
    }
    key_label = st.selectbox("Key to analyse", list(key_map.keys()))
    if st.button("Run Quantum Risk Analysis", type="primary"):
        with st.spinner("Running Qiskit period-finding simulation…"):
            st.session_state["quantum_risk_report"] = estimate_quantum_risk(key_map[key_label])

    report = st.session_state.get("quantum_risk_report")
    if report:
        st.markdown(
            f"<p class='{risk_class(report['risk_score'])}'>Quantum Risk: {report['risk_score']}</p>",
            unsafe_allow_html=True,
        )
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Break Year",         str(report["projected_break_year"]))
        c2.metric("Logical Qubits",     f"{report['logical_qubits_real']:,}")
        c3.metric("Physical Qubits",    f"{report['physical_qubits_real']:,}")
        c4.metric("Gate Depth (real)",  f"{report['gate_depth_real']:,}")
        with st.expander("Circuit diagram"):
            st.code(report["circuit_diagram"], language=None)
        counts_df = (
            pd.DataFrame({"state": list(report["sim_counts"].keys()),
                          "shots": list(report["sim_counts"].values())})
            .sort_values("state")
        )
        st.caption("Measurement counts (1 024 shots)")
        st.bar_chart(counts_df.set_index("state")["shots"])

    # ── 2. PQC Defense Demo ────────────────────────────────────────────────
    st.markdown("### PQC Defense Demo")
    col_before, col_after = st.columns(2)
    col_before.write("**Before — RSA-512 vault**")
    col_before.json({
        "encryption": _DEMO_VAULT["vault_metadata"]["encryption"],
        "transactions": len(_DEMO_VAULT["transactions"]),
    })

    if report and report["risk_score"] in {"HIGH", "CRITICAL"}:
        if st.button("Activate PQC Defense", type="primary"):
            buf = io.StringIO()
            with st.spinner("Re-encrypting with ML-KEM-768…"):
                with contextlib.redirect_stdout(buf):
                    st.session_state["pqc_secured_vault"] = defend_vault(_DEMO_VAULT, report)
            st.session_state["pqc_log"] = buf.getvalue()

    secured = st.session_state.get("pqc_secured_vault")
    if secured:
        col_after.write("**After — ML-KEM-768 vault**")
        col_after.json({
            "encryption":  secured["vault_metadata"]["encryption"],
            "pqc_status":  secured["transactions"][0]["pqc_status"],
            "transactions": len(secured["transactions"]),
        })
        with st.expander("Full secured vault JSON"):
            st.json(secured)
        st.caption(st.session_state.get("pqc_log", ""))
    elif report is None:
        st.info("Run Quantum Risk Analysis above first.")

    # ── 3. Attack Timeline ─────────────────────────────────────────────────
    st.markdown("### RSA Break Year Timeline")
    milestones = [(512, 2026, "CRITICAL"), (1024, 2029, "HIGH"),
                  (2048, 2033, "MEDIUM"),  (4096, 2040, "LOW")]
    fig, ax = plt.subplots(figsize=(9, 2.6))
    ax.set_facecolor("#f8fafc"); fig.patch.set_facecolor("#f8fafc")
    ax.axhline(0, color="#475467", lw=1.5)
    for i, (bits, yr, risk) in enumerate(milestones):
        c = _RISK_COLORS[risk]
        ax.scatter(yr, 0, s=180, color=c, zorder=3)
        ax.annotate(
            f"RSA-{bits}\n{yr}", xy=(yr, 0),
            xytext=(yr, 0.12 if i % 2 == 0 else -0.17),
            ha="center", va="bottom" if i % 2 == 0 else "top",
            fontsize=8, color=c, fontweight="bold",
            arrowprops=dict(arrowstyle="-", color=c, lw=1),
        )
    ax.axvline(2026, color="#344054", lw=1, ls="--", alpha=0.6)
    ax.text(2026.2, 0.21, "Now", fontsize=8, color="#344054")
    ax.set(xlim=(2024, 2043), ylim=(-0.32, 0.32), xlabel="Year")
    ax.set_yticks([])
    ax.set_title("Projected RSA Break Year by Key Size", fontsize=10)
    st.pyplot(fig); plt.close(fig)

    # ── 4. Innovative Circuit Demos ────────────────────────────────────────
    st.markdown("### Quantum Attack Circuit Demos")
    circuit_choice = st.selectbox(
        "Circuit", ["Shor's RSA Factoring (N=15 proxy)", "Grover's AES Key Attack"]
    )
    kwargs: dict[str, Any] = {}
    if circuit_choice == "Grover's AES Key Attack":
        kwargs["n_key_bits"] = st.slider("AES key bits (sim)", 2, 6, 4)
    ctype = "shor_factoring" if "Shor" in circuit_choice else "grover_aes"

    if st.button("Run Circuit Demo"):
        with st.spinner("Simulating on Aer…"):
            st.session_state["circuit_demo"] = run_innovative_circuit_demo(ctype, **kwargs)

    demo = st.session_state.get("circuit_demo")
    if demo and demo["circuit_type"] == ctype:
        st.info(demo["interpretation"])
        d1, d2 = st.columns(2)
        d1.metric("Circuit Depth", demo["depth"])
        d2.metric("Qubits", demo["num_qubits"])
        if ctype == "shor_factoring":
            rf = demo["extra"]["recovered_factors"]
            if rf["verified"]:
                st.success(f"Recovered factors: p={rf['p']}, q={rf['q']} — verified {rf['p']}×{rf['q']}={demo['extra']['N']}")
        with st.expander("Circuit diagram"):
            st.code(demo["circuit_diagram"], language=None)
        top = sorted(demo["sim_counts"].items(), key=lambda x: x[1], reverse=True)[:16]
        st.bar_chart(pd.DataFrame(top, columns=["state", "shots"]).set_index("state"))


def main() -> None:
    configure_page()
    st.title("Quantum Payment Security Auditor")

    tab_score, tab_scenarios, tab_scorecard, tab_benchmark, tab_export, tab_quantum = st.tabs(
        ["Score Payment", "Compare Scenarios", "Algorithm Scorecard", "Benchmark", "Export", "Quantum Threat Engine"]
    )

    with tab_score:
        render_transaction_tab()
    with tab_scenarios:
        render_scenario_tab()
    with tab_scorecard:
        render_scorecard_tab()
    with tab_benchmark:
        render_benchmark_tab()
    with tab_export:
        render_export_tab()
    with tab_quantum:
        render_quantum_tab()


if __name__ == "__main__":
    main()
