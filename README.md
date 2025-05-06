# 🔏 Blind Signature Protocol – Python Command line and GUI Demo

This project is a graphical simulation of the **Blind Signature Protocol** using Python and the RSA cryptosystem. It provides two separate GUIs: one for the **Issuer** and another for the **Prover**, allowing users to explore the privacy-preserving mechanism behind blind signatures in an interactive, step-by-step way.

## 📘 What is a Blind Signature?

A blind signature is a type of digital signature where the content of a message is hidden (blinded) before it is signed. The signer (Issuer) does not see the actual content, yet the resulting signature can still be verified by a third party using the public key. It’s used in applications such as:

- 🗳️ **Electronic Voting**
- 💸 **Digital Cash**
- 🔐 **Privacy-Preserving Authentication**

## 📖 Protocol Summary

1. **Issuer** generates an RSA key pair and shares the **public key**.
2. **Prover** blinds a message using a random value `r` and sends the **blinded message** `m′`.
3. **Issuer** signs `m′` and sends the **blinded signature** `s′` back.
4. **Prover** unblinds the signature to obtain the valid **signature** `s`.
5. **Prover** verifies `s` using the original message `m` and the Issuer's public key.

### 🧮 Mathematical Formulation

- **Blinding:**  
  `m′ = m · r^e mod n`

- **Signature:**  
  `s′ = (m′)^d mod n`

- **Unblinding:**  
  `s = s′ · r⁻¹ mod n`

- **Verification:**  
  `s^e mod n == m`


## 🎯 Features

- Separate GUIs for **Issuer** and **Prover**.
- Step-by-step and full execution modes.
- Visual logging of every cryptographic step with emojis and explanations.
- Use of `Crypto` for RSA key generation and modular arithmetic.
- Simple `socket`-based networking between Issuer and Prover.

---

## 🖥️ Demo Screenshots

| Issuer GUI                             | Prover GUI                             |
|---------------------------------------|----------------------------------------|
| ![Issuer Screenshot](imgs/issuer.png) | ![Prover Screenshot](imgs/prover.png) |

---

## 🔧 Files Overview

- `issuer_gui.py` – GUI and logic for the **signer (Issuer)**.
- `prover_gui.py` – GUI and logic for the **message author (Prover)**.
- `issuer.py` –  command line logic for the **signer (Issuer)**.
- `prover.py` – command line logic for the **message author (Prover)**.
- `imgs/` – Contains **protocol diagrams** and **GUI screenshots**.
- `README.md` – You're reading it!


## 🚀 How to Run

### 1. Clone the repository

```bash
git clone https://github.com/imiguelrodriguez/BlindSignatures.git
cd BlindSignatures
```
### 2. Run the Issuer

```bash
python issuer_gui.py
```

### 2. Run the Prover

```bash
python prover_gui.py
```