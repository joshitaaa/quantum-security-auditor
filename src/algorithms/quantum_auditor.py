"""
Quantum Threat Module — Automated Quantum Cryptographic Auditor (AQCA)
Simulates Shor's Algorithm period-finding via QFT to assess RSA key vulnerability.
"""

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
from qiskit.circuit.library import QFT
import numpy as np
import math


def build_period_finding_circuit(n_qubits: int, a: int, N: int) -> QuantumCircuit:
    """
    Constructs a simplified period-finding circuit using QFT.
    Simulates the quantum phase estimation core of Shor's algorithm.
    
    Args:
        n_qubits: counting register size (determines precision)
        a:        base for modular exponentiation a^x mod N
        N:        modulus to factor (simulated RSA key size proxy)
    """
    # Register 1: counting register (superposition of phases)
    qr_count = QuantumRegister(n_qubits, name='count')
    # Register 2: work register (mod-exp oracle output)
    qr_work  = QuantumRegister(math.ceil(math.log2(N + 1)), name='work')
    cr       = ClassicalRegister(n_qubits, name='meas')

    qc = QuantumCircuit(qr_count, qr_work, cr)

    # Step 1: Initialize counting register in superposition
    qc.h(qr_count)

    # Step 2: Initialize work register to |1⟩
    qc.x(qr_work[0])

    # Step 3: Controlled modular exponentiation (simplified oracle)
    # Real Shor's uses full modular arithmetic; here we approximate
    # phase kickback by rotating work qubits proportional to a^(2^k) mod N
    for k, ctrl in enumerate(qr_count):
        phase = (2 * np.pi * pow(a, 2**k, N)) / N
        qc.cp(phase, ctrl, qr_work[0])

    # Step 4: Inverse QFT on counting register
    qc.append(QFT(n_qubits, inverse=True).to_gate(label='QFT†'), qr_count)

    # Step 5: Measure counting register
    qc.measure(qr_count, cr)

    return qc


def estimate_quantum_risk(key_bits: int) -> dict:
    """
    Runs the AQCA circuit and returns a structured risk report.
    
    Args:
        key_bits: RSA key size in bits (e.g. 512, 1024, 2048)
    """
    # Shor's requires ~2n qubits for an n-bit RSA key
    # We simulate a proxy factoring problem: N=15, a=7 (textbook QC example)
    # and extrapolate qubit/gate depth requirements for real key sizes

    N_sim, a_sim = 15, 7
    n_qubits_sim = 4   # counting register for N=15

    qc = build_period_finding_circuit(n_qubits_sim, a_sim, N_sim)

    simulator = AerSimulator()
    from qiskit import transpile
    compiled = transpile(qc, simulator)
    job = simulator.run(compiled, shots=1024)
    result = job.result()
    counts = result.get_counts()

    # Extract most probable period candidate
    top_state = max(counts, key=counts.get)
    measured_int = int(top_state, 2)
    
    # Extrapolate real attack cost from simulation
    sim_gate_depth = compiled.depth()
    sim_qubit_count = compiled.num_qubits

    # Physical qubit estimate: ~1000 physical qubits per logical qubit (surface code)
    logical_qubits_needed = 2 * key_bits
    physical_qubits_needed = logical_qubits_needed * 1000  # surface code overhead
    gate_depth_real = key_bits ** 3  # polynomial scaling of Shor's

    # Time-to-failure estimate (years until quantum hardware reaches this scale)
    # Based on IBM/Google roadmap projections
    qubit_milestones = {
        512:  {"year": 2026, "physical_q": 1_024_000},
        1024: {"year": 2029, "physical_q": 2_048_000},
        2048: {"year": 2033, "physical_q": 4_096_000},
    }
    ttf = qubit_milestones.get(key_bits, {"year": "Unknown", "physical_q": physical_qubits_needed})

    risk_score = "CRITICAL" if key_bits <= 512 else "HIGH" if key_bits <= 1024 else "MEDIUM"

    return {
        "key_bits":              key_bits,
        "risk_score":            risk_score,
        "sim_circuit_depth":     sim_gate_depth,
        "sim_qubit_count":       sim_qubit_count,
        "sim_counts":            counts,
        "measured_period_proxy": measured_int,
        "logical_qubits_real":   logical_qubits_needed,
        "physical_qubits_real":  ttf["physical_q"],
        "projected_break_year":  ttf["year"],
        "gate_depth_real":       gate_depth_real,
        "circuit_diagram":       qc.draw(output='text').__str__(),
    }
