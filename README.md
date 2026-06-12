# quantum-security-auditor

## Setup & Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. (Optional) Real Kyber support
Install liboqs for actual ML-KEM-768:
https://github.com/open-quantum-safe/liboqs-python

### 3. Run the auditor
```bash
cd src
python main.py
```

### 4. Outputs
- Terminal: quantum circuit diagram, risk report, PQC upgrade log
- `data/bank_vault_pqc_secured.json`: re-encrypted vault

### 5. Demo Flow
Run with RSA-512 (triggers CRITICAL), then change key_bits to 4096 in main.py to see the MEDIUM path.