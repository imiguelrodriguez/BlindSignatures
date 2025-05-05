import tkinter as tk
import socket
from Crypto.Util.number import getRandomRange, inverse

HOST = 'localhost'
PORT = 5001

def run_protocol():
    try:
        # Connect to Issuer
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))

        # Step 1: Receive public key
        data = client.recv(1024 + 2 + 1024)
        n_bytes, e_bytes = data.split(b'||')
        n = int.from_bytes(n_bytes, 'big')
        e = int.from_bytes(e_bytes, 'big')
        output_text.set(f"1. Received public key:\nn = {n}\ne = {e}")

        # Step 2: Enter message and blind it
        m = int(entry.get())
        r = getRandomRange(2, n)
        m_prime = (m * pow(r, e, n)) % n
        client.send(m_prime.to_bytes(256, 'big'))
        output_text.set(output_text.get() + f"\n\n2. Blinded message:\nm = {m}\nr = {r}\nm' = {m_prime} as  m' = (m * r) mod n")

        # Step 3: Receive s′ and unblind
        s_prime = int.from_bytes(client.recv(4096), 'big')
        s = (s_prime * inverse(r, n)) % n
        output_text.set(output_text.get() + f"\n\n3. Received s′ = {s_prime}\n4. Unblinded s = {s}")

        # Step 4: Verify
        valid = pow(s, e, n) == m
        output_text.set(output_text.get() + f"\n\n5. Signature valid? {valid}")
        client.close()

    except Exception as e:
        output_text.set(f"Error: {e}")

# GUI
root = tk.Tk()
root.title("Prover GUI – Blind Signature")

tk.Label(root, text="Enter message m (integer):").pack()
entry = tk.Entry(root)
entry.pack()

tk.Button(root, text="Run Blind Signature Protocol", command=run_protocol).pack(pady=10)

output_text = tk.StringVar()
output = tk.Label(root, textvariable=output_text, justify='left', anchor='w', wraplength=500)
output.pack()

root.mainloop()
