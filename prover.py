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
    s.connect((HOST, PORT))

    # Receive public key
    pubkey_data = s.recv(1024)
    pubkey = RSA.import_key(pubkey_data)
    n = pubkey.n
    e = pubkey.e

    print("\nStart sending messages for blind signing.")
    print("Type 'exit' to quit.\n")

    while True:
        message = input("Message to sign > ")
        if message.lower() == 'exit':
            s.sendall(b"exit")
            print("Session ended.")
            break

        m = hash_message(message)

        r = getRandomRange(2, n - 1)
        r_e = pow(r, e, n)
        m_prime = (m * r_e) % n

        s.sendall(str(m_prime).encode())
        s_prime = int(s.recv(4096).decode())

        r_inv = inverse(r, n)
        s_final = (s_prime * r_inv) % n

        tamper = input("Tamper with signature? (y/n): ").strip().lower()
        if tamper == 'y':
            s_final = (s_final + 1) % n  # Corrupt it slightly

        print(f"Signature: {s_final}")
        try:
            assert pow(s_final, e, n) == m
            print("→ Signature verified ✅\n")
        except AssertionError:
            print("→ Signature failed ❌\n")