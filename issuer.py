# https://datatracker.ietf.org/doc/rfc9474/
# issuer.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Generate RSA key pair
key = RSA.generate(2048)
public_key = key.publickey()

HOST = 'localhost'
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print("Issuer ready...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        # Send public key
        conn.sendall(public_key.export_key())

        # Receive blinded message m'
        m_prime = int(conn.recv(4096).decode())
        print(f"Received m': {m_prime}")

        # Sign it: s' = (m')^d mod n
        s_prime = pow(m_prime, key.d, key.n)
        conn.sendall(str(s_prime).encode())
        print(f"Sent s': {s_prime}")
