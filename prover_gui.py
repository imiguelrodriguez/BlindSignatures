import tkinter as tk
from tkinter import messagebox
import socket

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomRange, inverse

HOST = 'localhost'
PORT = 5001

# === Globals ===
client = None
n = e = r = m = s_prime = s = None
current_step = 0

# === GUI Setup ===
root = tk.Tk()
root.title("Prover GUI – Blind Signature")

tk.Label(root, text="Enter message m:", font=("Helvetica", 12)).pack(pady=(10, 0))
entry = tk.Entry(root, font=("Courier", 12), width=30)
entry.pack(pady=5)

def hash_message(message):
    hash_obj = SHA256.new(message.encode())
    return int.from_bytes(hash_obj.digest(), byteorder='big')

def update_log(msg):
    log_box.config(state='normal')
    log_box.insert(tk.END, msg + '\n\n')
    log_box.see(tk.END)
    log_box.config(state='disabled')

def full_protocol():
    step_1_connect_and_receive()
    step_2_blind_message()
    step_3_receive_signature()
    step_4_unblind_and_verify()

# === Protocol Steps ===
def step_by_step_protocol():
    global current_step
    if current_step == 0:
        step_1_connect_and_receive()
    elif current_step == 1:
        step_2_blind_message()
    elif current_step == 2:
        step_3_receive_signature()
    elif current_step == 3:
        step_4_unblind_and_verify()
    else:
        update_log("✅ Protocol already completed.")
    current_step += 1

def step_1_connect_and_receive():
    global client, n, e
    message = entry.get().strip()

    if not message:
        messagebox.showwarning("Input Required", "Please enter a message.")
        return

    try:
        update_log("🔌 Step 1: Connecting to Issuer...")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        # Receive public key
        pubkey_data = client.recv(1024)
        pubkey = RSA.import_key(pubkey_data)
        n = pubkey.n
        e = pubkey.e
        update_log(f"✔ Received public key:\nn = {n}\ne = {e}")
    except Exception as ex:
        update_log(f"❌ Connection failed: {ex}")

def step_2_blind_message():
    global m, r, n, e
    message = entry.get().strip()
    m = hash_message(str(message))
    r = getRandomRange(2, n - 1)
    m_prime = (m * pow(r, e, n)) % n
    client.sendall(str(m_prime).encode())
    update_log(f"🔒 Step 2: Sent blinded message m′:\n m' = m · r^e mod n = {m_prime}")

def step_3_receive_signature():
    global s_prime
    s_prime = int(client.recv(4096).decode())
    update_log(f"📩 Step 3: Received s′ = {s_prime}")

def step_4_unblind_and_verify():
    global s
    s = (s_prime * inverse(r, n)) % n
    valid = pow(s, e, n) == m
    update_log(f"🔓 Step 4: Unblinded s:\n s = s' · r^(-1) mod n = {s}")
    update_log(f"✅ Signature valid? {'✔ Yes' if valid else '✘ No'}")
    client.close()
color1 = "#424242"  # Teal (button background)
color2 = "#ECEFF1"  # Darker teal (on hover)
text_color = "black"
highlight_color = "#004D40"

# === Step-by-step Button ===

tk.Button(root, text="Run Step-by-step Protocol", command=step_by_step_protocol,
          font=("Helvetica", 12, "bold"),
          background=color1, foreground='white',
          activebackground=color2, activeforeground=text_color,
          highlightcolor=highlight_color, highlightthickness=2,
          border=0, cursor='hand2', highlightbackground=color2).pack(pady=10)

# === Full protocol Button ===
tk.Button(root, text="Run Full Protocol", command=full_protocol,
          font=("Helvetica", 12, "bold"),
          background=color1, foreground='white',
          activebackground=color2, activeforeground=text_color,
          highlightcolor=highlight_color, highlightthickness=2,
          border=0, cursor='hand2', highlightbackground=color2).pack(pady=10)

log_label = tk.Label(root, text="Protocol Log", font=("Helvetica", 14, "bold"))
log_label.pack(pady=(10, 0))

log_box = tk.Text(root, wrap='word', height=20, width=80, bg="#f4f4f4", font=("Courier", 10))
log_box.pack(padx=10, pady=10)
log_box.config(state='disabled')
root.mainloop()
