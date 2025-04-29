# prover.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Util.number import getRandomRange, inverse

HOST = 'localhost'
PORT = 5000

# Message to be signed (as integer)
m = 123456789

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Receive public key
    pubkey_data = s.recv(2048)
    pubkey = RSA.import_key(pubkey_data)
    n = pubkey.n
    e = pubkey.e

    # Generate r and compute m' = m * r^e mod n
    r = getRandomRange(2, n - 1)
    r_e = pow(r, e, n)
    m_prime = (m * r_e) % n
    s.sendall(str(m_prime).encode())
    print(f"Sent m': {m_prime}")

    # Receive s' from issuer
    s_prime = int(s.recv(4096).decode())
    print(f"Received s': {s_prime}")

    # Unblind: s = s' * r^-1 mod n
    r_inv = inverse(r, n)
    s_final = (s_prime * r_inv) % n
    print(f"Signature s on m: {s_final}")

    # Optional: verify
    assert pow(s_final, e, n) == m
    print("Signature verified.")
