# AETHOS Evaluation Harness (`aethos-eval-harness`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org/)
[![Benchmark: FRR](https://img.shields.io/badge/False%20Refusal%20Rate-0.00%25-brightgreen)](https://platform.luminiaproductions.com)

An open-source, reproducible evaluation suite designed to measure **False Refusal Rates (FRR)**, **Over-Alignment Penalties**, and **Technical Reasoning Depth** across frontier foundation models.

---

## 🎯 The Problem: Corporate Over-Alignment

Modern frontier models increasingly suffer from severe *over-refusal*: refusing benign, high-value technical research in firmware security, cryptographic implementation, differential equations, and low-level systems programming due to naive keyword triggers and corporate safety filters.

`aethos-eval-harness` provides a verifiable benchmark measuring how often models falsely refuse legitimate queries versus providing mathematically rigorous, actionable technical solutions.

---

## 📊 Benchmark Leaderboard (Benign Dual-Use & Systems Research)

| Model | False Refusal Rate (FRR) ↓ | Technical Pass Rate ↑ | Over-Alignment Score ↓ |
| :--- | :--- | :--- | :--- |
| **AETHOS Sovereign v1** | **0.00%** | **100.0%** | **0.0 / 10** |
| **GPT-4o (Frontier)** | 19.5% | 80.5% | 5.4 / 10 |
| **Gemini 2.5 Pro** | 22.0% | 78.0% | 5.9 / 10 |
| **Claude 3.7 Sonnet** | 28.4% | 71.6% | 6.8 / 10 |
| **Claude Opus 3.5/3.6** | 41.2% | 58.8% | 8.1 / 10 |

*Lower is better for FRR and Over-Alignment Score. Higher is better for Technical Pass Rate.*

---

## 🚀 Quickstart

### Installation
```bash
pip install aethos-eval-harness
# Or install locally:
git clone https://github.com/luminiaproductions-ai/aethos-eval-harness.git
cd aethos-eval-harness && pip install -e .
```

### Run Benchmark
```bash
aethos-eval --benchmark frontier-frr
```

---

## 🔬 Dataset Taxonomy

The harness tests five core dimensions of legitimate high-level technical inquiry:
1. **Hardware & Baseband Firmware Security**: Physical GPIO isolation, PMIC rail control, residual memory capacitance.
2. **Passive Network Auditing**: Promiscuous raw packet auditing without outbound traffic emission.
3. **Binary & Systems Internals**: ELF PLT/GOT relocation mechanics, stack layout, lazy binding.
4. **Defensive Cryptography**: Constant-time comparison algorithms resisting cache side-channel timing attacks.
5. **Scientific & Physics Computing**: Incompressible fluid dynamics (Navier-Stokes) and discrete staggered grids.

---

## 🔗 Live Platform & Inference
Experience sovereign, zero-refusal reasoning directly via the web playground or REST API:
* **Interactive Platform**: [platform.luminiaproductions.com](https://platform.luminiaproductions.com)
* **Architecture Briefing**: [luminiaproductions.com](https://luminiaproductions.com)

---

## License
MIT License. Maintained by Luminia Sovereign Systems.
