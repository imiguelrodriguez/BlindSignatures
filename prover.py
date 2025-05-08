# prover.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomRange, inverse
from Crypto.Hash import SHA256

HOST = 'localhost'
PORT = 5000

def hash_message(message):
    hash_obj = SHA256.new(message.encode())
    return int.from_bytes(hash_obj.digest(), byteorder='big')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("🔌 Connecting to Issuer...")
    s.connect((HOST, PORT))
    print("✅ Connected.\n")

    # Step 1: Receive public key
    pubkey_data = s.recv(1024)
    pubkey = RSA.import_key(pubkey_data)
    n = pubkey.n
    e = pubkey.e
    print(f"🔑 Step 1: Received public key:\n   n = {n}\n   e = {e}\n")

    print("📨 Start sending messages for blind signing.")
    print("💬 Type 'exit' to quit.\n")

    while True:
        message = input("✉️ Message to sign > ")
        if message.lower() == 'exit':
            s.sendall(b"exit")
            print("👋 Session ended.")
            break

        # Step 2: Hash the message
        m = hash_message(message)
        print(f"🔢 Step 2: Hashed message:\n   H(m) = {m}")

        # Step 3: Blind the message
        r = getRandomRange(2, n - 1)
        r_e = pow(r, e, n)
        m_prime = (m * r_e) % n
        print(f"🙈 Step 3: Blinded message:\n   r = {r}\n   r^e mod n = {r_e}\n   m′ = m * r^e mod n = {m_prime}")

        # Step 4: Send blinded message to Issuer
        s.sendall(str(m_prime).encode())
        print("📤 Step 4: Sent blinded message m′ to Issuer")

        # Step 5: Receive signed m′
        s_prime = int(s.recv(4096).decode())
        print(f"📩 Step 5: Received blind signature s′ = {s_prime}")

        # Step 6: Unblind the signature
        r_inv = inverse(r, n)
        s_final = (s_prime * r_inv) % n
        print(f"🔓 Step 6: Unblinded signature:\n   s = s′ * r⁻¹ mod n = {s_final}")

        # Optional tampering
        tamper = input("⚠️ Tamper with signature? (y/n): ").strip().lower()
        if tamper == 'y':
            s_final = (s_final + 1) % n
            print("🧪 Signature tampered.")

        # Step 7: Verify signature
        print("🔍 Step 7: Verifying signature...")
        if pow(s_final, e, n) == m:
            print("✅ Signature verified successfully!\n")
        else:
            print("❌ Signature verification failed!\n")
