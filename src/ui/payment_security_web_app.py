"""
Interactive Streamlit web app for payment transaction security scoring.

Run with:
    streamlit run src/ui/payment_security_web_app.py
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pandas as pd
import streamlit as st

from algorithms.crypto_algorithms import ALGORITHM_PROFILES, list_algorithm_profiles, score_encrypted_transaction
from benchmarks.algorithm_benchmark import attack_estimates_as_dicts, benchmark_results_as_dicts, toy_crack_results_as_dicts


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


def main() -> None:
    configure_page()
    st.title("Quantum Payment Security Auditor")

    tab_score, tab_scenarios, tab_scorecard, tab_benchmark, tab_export = st.tabs(
        ["Score Payment", "Compare Scenarios", "Algorithm Scorecard", "Benchmark", "Export"]
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


if __name__ == "__main__":
    main()
