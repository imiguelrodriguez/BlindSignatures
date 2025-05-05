import tkinter as tk
import socket
import threading
from Crypto.PublicKey import RSA

HOST = 'localhost'
PORT = 5001

# Generate RSA key pair
key = RSA.generate(1024)
n, e, d = key.n, key.e, key.d

# GUI setup
root = tk.Tk()
root.title("Issuer GUI – Blind Signature")

output_text = tk.StringVar()
output = tk.Label(root, textvariable=output_text, justify='left', anchor='w', wraplength=500)
output.pack(padx=10, pady=10)

output_text.set(f"Issuer Public Key:\nn = {n}\ne = {e}\n\nWaiting for Prover...")

def handle_connection():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(1)
        conn, addr = server.accept()
        with conn:
            output_text.set(output_text.get() + f"\n\nConnected to {addr}")

            # Step 1: Send public key
            conn.send(n.to_bytes(256, 'big') + b'||' + e.to_bytes(256, 'big'))
            output_text.set(output_text.get() + "\n\nSent public key to Prover")

            # Step 2: Receive blinded message m'
            m_prime = int.from_bytes(conn.recv(4096), 'big')
            output_text.set(output_text.get() + f"\n\nReceived m′ = {m_prime}")

            # Step 3: Compute s′ = (m′)^d mod n
            s_prime = pow(m_prime, d, n)
            output_text.set(output_text.get() + f"\n\nComputed s′ = {s_prime} as s′ = (m′)^d mod n")

            # Step 4: Send s′ back
            conn.send(s_prime.to_bytes(256, 'big'))
            output_text.set(output_text.get() + "\n\nSent s′ back to Prover")

threading.Thread(target=handle_connection, daemon=True).start()

root.mainloop()
