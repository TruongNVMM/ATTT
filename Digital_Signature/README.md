# Digital Signature System

A pure-Python implementation of a secure **Sign-and-Encrypt** communication workflow using **DSA** (Digital Signature Algorithm) and **RSA** (Rivest–Shamir–Adleman) — built from scratch without any third-party cryptographic libraries.

---

## Overview

This system demonstrates a complete end-to-end **secure message transmission pipeline** where:

- The **Sender** signs the message with their DSA private key, then encrypts the package using the Receiver's RSA public key.
- The **Receiver** decrypts the package with their RSA private key, then verifies the DSA signature using the Sender's public key.

This design guarantees:
| Property | Mechanism |
|---|---|
| **Confidentiality** | RSA encryption (only Receiver can decrypt) |
| **Integrity** | DSA signature (any change invalidates signature) |
| **Authenticity** | DSA signing with Sender's private key |

---

## Project Structure

```
Digital_Signature/
├── pipeline.py                  # Main entry point: test Case 1 & Case 2
│
├── algorithm/
│   ├── sender/
│   │   └── sender.py            # Sender class: Sign & Encrypt workflow
│   └── receiver/
│       └── receiver.py          # Receiver class: Decrypt & Verify workflow
│
├── key/
│   ├── generate_keys.py         # CLI tool to generate key pairs
│   ├── sender/
│   │   ├── private_key_sender.pem
│   │   └── public_key_sender.pem
│   └── receiver/
│       ├── private_key_receiver.pem
│       └── public_key_receiver.pem
│
├── src/
│   ├── asymmetric/
│   │   ├── DSA/DSA.py           # DSA implementation
│   │   ├── RSA/RSA.py           # RSA implementation
│   │   └── ECDSA/               # ECDSA implementation
│   ├── hash/
│   │   ├── SHA256.py            # SHA-256 hash
│   │   ├── RIPEMD160.py         # RIPEMD-160 hash
│   │   └── TIGER192.py          # TIGER-192 hash
│   └── symmetric/               # Symmetric cipher implementations
│
└── test_vector/
    ├── DSA/                     # NIST FIPS 186-3 DSA test vectors (SigGen, SigVer, ...)
    ├── RSA/                     # RSA test vectors
    ├── ECDSA/                   # ECDSA test vectors
    ├── benchmark_dsa.py         # DSA benchmark
    └── benchmark_rsa.py         # RSA benchmark
    
```

---

## Workflow

### Sender (Sign & Encrypt)

```
Plain Message
     │
     ▼
[Block 2] DSA Sign  ◄─── PriKey(S)
     │   Generates signature (r, s)
     ▼
[Block 3] Pack
     │   Bundles: { message, signature, PubKey(S) }
     ▼
[Block 4] RSA Encrypt  ◄─── PubKey(R)
     │   Full JSON payload encrypted
     ▼
[Block 5] Base64 Encode → Network Transmission
```
![Signature and Encryption](imgs/Signature_and_Encryption.png)

### Receiver (Decrypt & Verify)

```
Encoded Network Packet
     │
     ▼
[Block 1] Base64 Decode + RSA Decrypt  ◄─── PriKey(R)
     │   Recovers packed JSON
     ▼
[Block 2] Unpack
     │   Extracts: message, signature (r, s), PubKey(S)
     ▼
[Block 3] DSA Verify  ◄─── PubKey(S) (from packet)
     │   Re-hashes message, compares signature
     ▼
 PASS / FAIL
```
![Decryption and Signature Verification](imgs/Decryption_and_Signature_Verification.png)

---

## Setup & Usage

### 1. Generate Keys

Run from the project root:

```bash
# Generate Sender keys (DSA)
python key/generate_keys.py --algorithm DSA --path key/sender --para sender

# Generate Receiver keys (RSA)
python key/generate_keys.py --algorithm RSA --path key/receiver --para receiver
```

Supported algorithms: `DSA`, `RSA`, `ECDSA`

### 2. Run Pipeline

```bash
git clone https://github.com/TruongNVMM/ATTT
cd Digital_Signature
python pipeline.py
```

You will be prompted to:
1. Enter your message
2. Choose a test case:
   - **`1`** — Normal flow: Sign → Encrypt → Decrypt → Verify
   - **`2`** — Tampered flow: Message is modified after signing → Verify FAILS

---

## Test Cases

### Case 1: Valid Message

```
Enter message: Hello
Enter index: 1

[*] Plain Message: 'Hello'

=> Signature and Encryption
[2] DSA Signing block completed. Signature generated.
[3] Pack block completed. Pack size: 479 bytes
[4] RSA Encryption block completed. Generated S&E Message.
[5] Ready for Transmission!

=> Decryption and Signature Verification
[1] RSA Decryption block completed. Recovered Packed data.
[2] Unpack block completed.
[3] Recovered Message: 'Hello'

=> Signature verified SUCCESSFULLY.
```

### Case 2: Tampered Message (Attack Simulation)

Simulates a **Man-in-the-Middle attack** where the attacker intercepts the packet, decrypts the RSA layer, modifies the message content, but **cannot forge the DSA signature** — causing verification to fail.

```
Enter message: Hello
Enter index: 2

[*] Plain Message: 'Hello'
...
[!] Simulation: Attacker tampered with the decrypted message!
[3] Recovered Message (Tampered): 'Hello World'

=> Signature verified FAILED. (Signature Mismatch!) Tampered message detected!
```

---

## Test Vectors & Benchmarks

The `test_vector/` directory contains official **NIST FIPS** test vectors for compliance validation and scripts to benchmark the algorithms.

### 1. DSA Benchmarking

The `test_vector/DSA/` directory contains official **NIST FIPS 186-3** test vectors:

| File | Purpose |
|---|---|
| `SigGen.rsp` | Known-answer test for signature generation |
| `SigGen.txt` | Includes intermediate values (`k`, `x`) for step-by-step tracing |
| `SigVer.rsp` | Known-answer test for signature verification (Pass/Fail) |
| `KeyPair.rsp` | Key pair generation validation |
| `PQGGen.rsp` | Domain parameter generation (`p`, `q`, `g`) |
| `PQGVer.rsp` | Domain parameter verification |

Run the DSA benchmark to validate the core DSA implementation and measure ops/sec against these vectors:

```bash
python test_vector/benchmark_dsa.py
```

### 2. RSA Benchmarking
Since a comprehensive test suite for Digital Signatures is unavailable, the benchmark will rely on RSA and DSA encryption and decryption algorithms.

The `test_vector/RSA/` directory contains official **NIST FIPS 186-2/3** test vectors for RSA (e.g. `SigGenRSA.rsp`, `SigVerRSA.rsp`).

Run the RSA benchmark to test raw mathematical throughput (up to 4096-bit keys) and validate the `RSA.py` class:

```bash
python test_vector/benchmark_rsa.py
```

---

## Key File Format

Keys are stored in a custom **PEM-like format** using Base64 encoding:

```
-----BEGIN DSA PRIVATE KEY-----
<Base64-encoded integer (DSA) or tuple (RSA)>
-----END DSA PRIVATE KEY-----
```

- **DSA keys**: Stored as a single integer (`x` for private, `y` for public)
- **RSA keys**: Stored as a tuple `(e, n)` for public or `(d, n)` for private

---

## Dependencies

This project uses **Python standard library only** — no third-party packages required.

```
Python >= 3.10
```

No `pip install` needed.
---

## Contributors
### Theoretical Foundations of Cryptography
#### Instructor: Dr. Tạ Thị Kim Huệ 
| Name        | ID          | Task        |
| :-----------| :-----------| :-----------|
| Nguyễn Việt Trường | 20234042 | Key and Test vector |
| Lê Minh Triết | 20234040 | Hash SHA256 |
| Vũ Đức Thuận | 20234039 | DSA algorithm |
| Hoàng Đức Trung | 20234041 | RSA algorithm |
| Vũ Ngọc Tuấn | 20234044 | Receiver block|
| Lê Nhật Trung | 202414953 | Sender block |

## Citation
```bibtex
@article{
  author    = {Ravneet Kaur , Amandeep Kaur - Assistant Professor in Department of Computer Science},
  title     = {DIGITAL SIGNATURE},
  year      = {2012},
  url       = {https://doi.org/10.1109/ICCS.2012.25}
}
```
---