# Python-Security-Scripts 🐍

A collection of basic Python scripts and utilities for common cybersecurity tasks, focusing on learning fundamentals.

---

## 💡 Project Purpose

This repository is a practical workspace for me to apply and solidify theoretical **cybersecurity** concepts through coding. Each script demonstrates a fundamental security principle, such as **data integrity** or **network reconnaissance**.

The goal is to build a verifiable, hands-on portfolio as I transition into the field.

## 🛠️ Utilities & Concepts Demonstrated

| Script Name | Security Concept | Description |
| :--- | :--- | :--- |
| **`hash_checker.py`** | **Data Integrity** | Calculates the SHA-256 hash of a file to verify it hasn't been tampered with. |
| **`port_scanner.py`** | **Network Reconnaissance** | Checks if common network ports (80, 443, 22, etc.) are open on a target IP or hostname. |

## 🚀 How to Run the Scripts (Usage)

To run any of the scripts in this repository, you will need **Python 3** installed on your system.

### 1. Clone the Repository

Open your terminal or command prompt and run:

```bash
git clone [https://github.com/CyberVortexX/Python-Security-Scripts.git](https://github.com/CyberVortexX/Python-Security-Scripts.git)
cd Python-Security-Scripts
```
### 2. Basic Port Scanner
Bash

# Example: Scan your local machine (127.0.0.1)
```python port_scanner.py 127.0.0.1
(You can replace 127.0.0.1 with any other IP or hostname you have permission to scan.)
```
📚 Key Learning Points
Networking: Implementing basic TCP socket connections and handling timeouts.

Cryptography: Utilizing the hashlib library for secure hash generation.

Error Handling: Using try...except blocks to handle file or network connection errors gracefully.
