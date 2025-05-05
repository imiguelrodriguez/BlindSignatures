# https://datatracker.ietf.org/doc/rfc9474/
# issuer.py
# issuer.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

HOST = 'localhost'
PORT = 5000

# Generate RSA keys
key = RSA.generate(2048)
n = key.n
d = key.d

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Issuer ready on {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        # Send public key
        conn.sendall(key.publickey().export_key())

        while True:
            data = conn.recv(4096)
            if not data:
                break
            if data.strip() == b"exit":
                print("Session closed by prover.")
                break

            m_prime = int(data.decode())
            s_prime = pow(m_prime, d, n)
            conn.sendall(str(s_prime).encode())
