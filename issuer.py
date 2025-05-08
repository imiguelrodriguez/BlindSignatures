# issuer.py
# Based on RFC 9474 – Blind RSA Signatures
import socket
from Crypto.PublicKey import RSA

HOST = 'localhost'
PORT = 5000

# 🔐 Generate RSA keys
print("🔐 Generating RSA key pair (2048 bits)...")
key = RSA.generate(2048)
n = key.n
d = key.d
print("✅ RSA keys generated.\n")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"📡 Issuer ready and listening on {HOST}:{PORT}\n")

    conn, addr = s.accept()
    with conn:
        print(f"🤝 Connected by {addr}\n")

        # Step 1: Send public key
        conn.sendall(key.publickey().export_key())
        print("📤 Step 1: Sent public key to Prover.")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            if data.strip() == b"exit":
                print("👋 Session closed by Prover.")
                break

            # Step 2: Receive blinded message m′
            m_prime = int(data.decode())
            print(f"📥 Step 2: Received blinded message m′ = {m_prime}")

            # Step 3: Compute s′ = (m′)^d mod n
            s_prime = pow(m_prime, d, n)
            print(f"🧮 Step 3: Computed s′ = (m′)^d mod n = {s_prime}")

            # Step 4: Send s′ back to Prover
            conn.sendall(str(s_prime).encode())
            print("📤 Step 4: Sent s′ back to Prover\n")
