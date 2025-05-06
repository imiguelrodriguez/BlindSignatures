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

n_text = tk.Text(key_frame, height=5, width=70, font=("Courier", 10), wrap="word")
n_text.grid(row=0, column=1, padx=5, pady=5)
n_text.insert(tk.END, str(n))
n_text.config(state='disabled', bg="#f0f0f0", relief='flat')

# Label and Text for e
e_label = tk.Label(key_frame, text="e:", font=("Helvetica", 12))
e_label.grid(row=1, column=0, sticky='ne', padx=5, pady=5)

e_text = tk.Text(key_frame, height=1, width=70, font=("Courier", 10), wrap="none")
e_text.grid(row=1, column=1, padx=5, pady=5)
e_text.insert(tk.END, str(e))
e_text.config(state='disabled', bg="#f0f0f0", relief='flat')


# === Status Log ===
log_label = tk.Label(root, text="Protocol Log", font=("Helvetica", 14, "bold"))
log_label.pack(pady=(10, 0))

log_box = tk.Text(root, wrap='word', height=20, width=80, bg="#f4f4f4", font=("Courier", 10))
log_box.pack(padx=10, pady=10)
log_box.config(state='disabled')

# === Log updater ===
def update_log(message):
    log_box.config(state='normal')
    log_box.insert(tk.END, message + '\n\n')
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
            update_log(f"🔌 Connected to Prover at {addr}")

            # Step 1: Send public key
            conn.sendall(key.publickey().export_key())
            update_log("📤 Sent public key to Prover")

            # Step 2: Receive blinded message m'
            m_prime_data = conn.recv(4096)
            m_prime = int(m_prime_data.decode())
            update_log(f"📥 Received blinded message:\nm′ = {m_prime}")

            # Step 3: Compute s′ = (m′)^d mod n
            s_prime = pow(m_prime, d, n)
            update_log(f"🧮 Computed s′:\ns′ = (m′)^d mod n = {s_prime}")

            # Step 4: Send s′ back
            conn.sendall(str(s_prime).encode())
            update_log("📤 Sent signed blinded message s′ back to Prover")


# Run the socket in a background thread
threading.Thread(target=handle_connection, daemon=True).start()

# Start the GUI main loop
root.mainloop()
