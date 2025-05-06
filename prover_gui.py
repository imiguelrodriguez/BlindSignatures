import tkinter as tk
from tkinter import messagebox
import socket
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

tk.Label(root, text="Enter message m (integer):", font=("Helvetica", 12)).pack(pady=(10, 0))
entry = tk.Entry(root, font=("Courier", 12), width=30)
entry.pack(pady=5)

log_label = tk.Label(root, text="Protocol Log", font=("Helvetica", 14, "bold"))
log_label.pack(pady=(10, 0))

log_box = tk.Text(root, wrap='word', height=15, width=80, bg="#f4f4f4", font=("Courier", 10))
log_box.pack(padx=10, pady=10)
log_box.config(state='disabled')

def update_log(msg):
    log_box.config(state='normal')
    log_box.insert(tk.END, msg + '\n')
    log_box.see(tk.END)
    log_box.config(state='disabled')

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
    if not message.isdigit():
        messagebox.showerror("Invalid Input", "Message must be an integer.")
        return

    try:
        update_log("🔌 Step 1: Connecting to Issuer...")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        data = client.recv(1024 + 2 + 1024)
        n_bytes, e_bytes = data.split(b'||')
        n = int.from_bytes(n_bytes, 'big')
        e = int.from_bytes(e_bytes, 'big')
        update_log(f"✔ Received public key:\nn = {n}\ne = {e}")
    except Exception as ex:
        update_log(f"❌ Connection failed: {ex}")

def step_2_blind_message():
    global m, r, n, e
    m = int(entry.get().strip())
    r = getRandomRange(2, n)
    m_prime = (m * pow(r, e, n)) % n
    client.send(m_prime.to_bytes((n.bit_length() + 7) // 8, 'big'))
    update_log(f"🔒 Step 2: Sent blinded message m′ = {m_prime}")

def step_3_receive_signature():
    global s_prime
    s_prime = int.from_bytes(client.recv(4096), 'big')
    update_log(f"📩 Step 3: Received s′ = {s_prime}")

def step_4_unblind_and_verify():
    global s
    s = (s_prime * inverse(r, n)) % n
    valid = pow(s, e, n) == m
    update_log(f"🔓 Step 4: Unblinded s = {s}")
    update_log(f"✅ Signature valid? {'✔ Yes' if valid else '✘ No'}")
    client.close()

# === Step-by-step Button ===
tk.Button(root, text="Run Step-by-step Protocol", command=step_by_step_protocol,
          font=("Helvetica", 12)).pack(pady=10)

root.mainloop()
