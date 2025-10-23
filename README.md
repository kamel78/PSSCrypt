# Authenticated Encryption from Packed Secret Sharing: One-Pass Lightweight Design with Provable Security

**Author:** Kamel Mohamed Faraoun  
**Affiliation:** Computer Science Department, EEDIS Laboratory,  
Djilalli Liabbes University, Sidi Bel Abbès, Algeria  
*kamel.faraoun@univ-sba.dz*  
## Overview

This repository provides the official implementation and benchmarking framework accompanying the research paper **“Authenticated Encryption from Packed Secret Sharing: One-Pass Lightweight Design with Provable Security.”** It introduces a lightweight authenticated encryption scheme based on **Packed Secret Sharing (PSS)** — a generalized variant of Shamir’s Secret Sharing that encodes multiple secrets within a single polynomial evaluation vector. Unlike conventional block or stream cipher designs, this approach achieves simultaneous encryption and authentication in one pass, maintaining **IND-CPA** and **IND-CCA** provable security with minimal computational and communication overhead. Designed for **IoT**, **wireless sensor**, and **embedded systems**, the implementation demonstrates significant improvements in speed, scalability, and efficiency over existing lightweight authenticated encryption schemes.

## Key Features

- **Packed Secret Sharing–based encryption:** multiple message blocks are processed within a compact polynomial structure.  
- **Integrated authentication:** ciphertext integrity and authenticity are embedded within the same encryption process.  
- **Provable IND-CPA and IND-CCA security:** formally derived from the security of the underlying pseudorandom permutation (PRP).  
- **Lightweight execution:** minimal polynomial and finite-field operations with reduced computational complexity.  
- **Scalable :** designed for efficient execution on both constrained and general-purpose platforms.  
- **Implemented over** \( GF(2^{128}) \) for high-performance arithmetic and strong resistance to side-channel leakage.

## Benchmarking Framework for AES-Based Authenticated Encryption Schemes

This repository contains a comprehensive benchmarking framework designed to evaluate and compare the performance, scalability, and sensitivity of several authenticated encryption schemes, including standard AES-based modes (GCM, CCM, OCB) and a proposed lightweight construction (AES-PSS). The framework was developed as part of the experimental study accompanying our paper, where multiple aspects of runtime behavior and cryptographic robustness are examined under varying security configurations.

The benchmark suite evaluates the following schemes:

- **AES-GCM** – Galois/Counter Mode  
- **AES-CCM** – Counter with CBC-MAC Mode  
- **AES-OCB** – Offset Codebook Mode  
- **AES-PSS** – Proposed lightweight construction  

All benchmarks can be executed at **128-bit** and **256-bit** security levels.

## Benchmark Categories

The main executable (`main.rs`) provides several routines accessible via a menu-driven interface:

| Option | Benchmark Type | Description |
|:------:|----------------|-------------|
| (1) | Runtime (128-bit) | Benchmarks throughput and latency of AES-GCM, AES-CCM, AES-OCB, and AES-PSS at 128-bit level. |
| (2) | Runtime (256-bit) | Same as above, for 256-bit level. |
| (3) | Sensitivity (Key/IV) | Measures robustness against small perturbations in key or IV. |
| (4) | Sensitivity (Tag/Auth) | Evaluates authentication tag sensitivity to input modifications. |
| (5) | Scalability | Measures relative runtime overhead when moving from 128-bit to 256-bit security. |
| (6) | AES Microbench | Performs fine-grained AES timing tests at 128/256-bit levels. |

## How to Run

### Prerequisites
- **Rust toolchain** (stable version)
- **Cargo** build system

### Build and Execute
```bash
git clone https://github.com/kamel78/PSSCrypt.git
cd psscrypt
cargo run --release
```
Running in `--release` mode is **highly recommended** for accurate timing measurements.

## Benchmark Output

Each benchmark automatically prints performance metrics to the console, including:

- **Throughput (MB/s)** for large plaintexts (1 GB)
- **Latency (ns/byte)** for small plaintexts (10 KB)
- **Runtime Overhead Ratio** between 128-bit and 256-bit configurations
- **Sensitivity Metrics** showing statistical variations under controlled bit flipping (1, 2, 4, 8 bits)

Example console output:
```
============================================================================
(1)- Runtime bench-marking of several implemented schemes in 128bit level.
(2)- Runtime bench-marking of several implemented schemes in 256bit level.
...
============================================================================
Please run in '--release' mode for accurate results.
```

## Experimental Motivation

The goal of this benchmarking framework is to assess:
1. **Efficiency** — measuring computational overhead and throughput scaling.
2. **Robustness** — evaluating sensitivity to key, IV, and authentication variations.
3. **Scalability** — quantifying runtime evolution with increasing security levels.

Results reported in the paper (see Table X) show that the proposed **AES-PSS construction** scales significantly better than conventional modes, demonstrating **lower relative overhead** when raising the security level from 128-bit to 256-bit.

## License

This project is released under the **MIT License**.  
You are free to use, modify, and distribute it with appropriate citation to the original paper.


## Author
**Kamel Mohamed**  
Security and Multimedia Research Team  
Computer Science Department, EEDIS Laboratory,  
Djilalli Liabbes University, Sidi Bel Abbès, Algeria  
*kamel.faraoun@univ-sba.dz*  
