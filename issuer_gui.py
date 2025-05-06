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

# === Title ===
title = tk.Label(root, text="Issuer Public Key", font=("Helvetica", 16, "bold"))
title.pack(pady=(10, 5))

# === Public Key Section ===
key_frame = tk.Frame(root)
key_frame.pack(pady=10)

# Label and Text for n
n_label = tk.Label(key_frame, text="n:", font=("Helvetica", 12))
n_label.grid(row=0, column=0, sticky='ne', padx=5, pady=5)

n_text = tk.Text(key_frame, height=3, width=70, font=("Courier", 10), wrap="word")
n_text.grid(row=0, column=1, padx=5, pady=5)
n_text.insert(tk.END, str(n))
n_text.config(state='disabled', bg="#f0f0f0", relief='flat')

# Label and Entry for e
tk.Label(key_frame, text="e:", font=("Helvetica", 12)).grid(row=1, column=0, sticky='e', padx=5, pady=5)
entry_e = tk.Entry(key_frame, width=60, font=("Courier", 10))
entry_e.grid(row=1, column=1, padx=5, pady=5)
entry_e.insert(0, str(e))
entry_e.config(state='readonly')

# === Status Log ===
log_label = tk.Label(root, text="Log", font=("Helvetica", 14, "bold"))
log_label.pack(pady=(10, 0))

log_box = tk.Text(root, wrap='word', height=10, width=80, bg="#f4f4f4", font=("Courier", 10))
log_box.pack(padx=10, pady=10)
log_box.config(state='disabled')

# === Log updater ===
def update_log(message):
    log_box.config(state='normal')
    log_box.insert(tk.END, message + '\n')
    log_box.see(tk.END)
    log_box.config(state='disabled')

update_log("Waiting for Prover...")

# === Handle connection logic ===
def handle_connection():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(1)
        conn, addr = server.accept()
        with conn:
            update_log(f"\nConnected to {addr}")

            # Step 1: Send public key
            key_size_bytes = (n.bit_length() + 7) // 8
            conn.send(n.to_bytes(key_size_bytes, 'big') + b'||' + e.to_bytes(key_size_bytes, 'big'))
            update_log("\nSent public key to Prover")

            # Step 2: Receive blinded message m'
            m_prime_data = conn.recv(4096)
            m_prime = int.from_bytes(m_prime_data, 'big')
            update_log(f"\nReceived m′ = {m_prime}")

            # Step 3: Compute s′ = (m′)^d mod n
            s_prime = pow(m_prime, d, n)
            update_log(f"\nComputed s′ = {s_prime} as s′ = (m′)^d mod n")

            # Step 4: Send s′ back
            conn.send(s_prime.to_bytes(key_size_bytes, 'big'))
            update_log("\nSent s′ back to Prover")

# Run the socket in a background thread
threading.Thread(target=handle_connection, daemon=True).start()

# Start the GUI main loop
root.mainloop()
