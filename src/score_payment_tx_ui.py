"""
Streamlit UI for scoring encrypted payment transactions.

Run with:
    streamlit run src/score_payment_tx_ui.py
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from algorithm_benchmark import benchmark_results_as_dicts
from crypto_algorithms import ALGORITHM_PROFILES, list_algorithm_profiles, score_encrypted_transaction


st.set_page_config(page_title="Quantum Payment Security Auditor", layout="wide")

st.title("Quantum Payment Security Auditor")

left, right = st.columns([1, 1])

with left:
    st.subheader("Payment Transaction Input")
    algorithm = st.selectbox("Encryption or signature algorithm", list(ALGORITHM_PROFILES.keys()), index=1)
    channel = st.selectbox("Payment channel", ["SWIFT_MT103", "ACH_CREDIT", "CARD", "WIRE", "PAYMENT"])
    amount_sgd = st.number_input("Payment amount (SGD)", min_value=0.0, value=250000.0, step=1000.0)
    encrypted_payload = st.text_area(
        "Encrypted transaction payload",
        height=180,
        placeholder="Paste base64 or hex ciphertext here",
    )

    if st.button("Score Transaction", type="primary"):
        result = score_encrypted_transaction(encrypted_payload, algorithm, amount_sgd, channel)
        st.session_state["score_result"] = result

with right:
    st.subheader("Security Score")
    result = st.session_state.get("score_result")
    if result:
        st.metric("Score", f"{result['score']}/100", result["risk_rating"])
        st.write(
            {
                "algorithm": result["algorithm"],
                "quantum_safe": result["quantum_safe"],
                "cipher_entropy": result["entropy"],
                "valid_encoding": result["valid_encoding"],
            }
        )
        st.write("Findings")
        for finding in result["findings"]:
            st.write(f"- {finding}")
        st.info(result["recommendation"])
    else:
        st.write("Enter an encrypted payment payload and score it.")

st.divider()

profiles = pd.DataFrame(list_algorithm_profiles())
st.subheader("Algorithm Security Scorecard")
st.dataframe(
    profiles[
        [
            "name",
            "primary_use",
            "nist_status",
            "quantum_safe",
            "security_level",
            "base_score",
            "production_role",
        ]
    ],
    use_container_width=True,
    hide_index=True,
)

st.subheader("Performance Comparison")
iterations = st.slider("Benchmark iterations", min_value=1, max_value=20, value=5)
if st.button("Run Benchmark"):
    with st.spinner("Running local benchmark..."):
        st.session_state["benchmark_results"] = benchmark_results_as_dicts(iterations)

if "benchmark_results" in st.session_state:
    st.dataframe(pd.DataFrame(st.session_state["benchmark_results"]), use_container_width=True, hide_index=True)
else:
    st.caption("Run the benchmark to compare local operation latency for RSA and PQC options.")
