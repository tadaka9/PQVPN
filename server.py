#!/usr/bin/env python3

import os
import socket

import oqs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "localhost"
PORT = 65432


def encrypt_message(key, message):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return nonce + encryptor.tag + ciphertext


def decrypt_message(key, encrypted):
    nonce = encrypted[:12]
    tag = encrypted[12:28]
    ciphertext = encrypted[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Server listening...")
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        # Receive client's public key
        pk_len = int.from_bytes(conn.recv(4), "big")
        pk = conn.recv(pk_len)
        print("Received client's public key")

        # Generate KEM and encapsulate
        kem = oqs.KeyEncapsulation("Kyber1024")
        ciphertext, shared_secret = kem.encap_secret(pk)
        print("Encapsulated shared secret")

        # Send ciphertext
        conn.send(len(ciphertext).to_bytes(4, "big"))
        conn.send(ciphertext)
        print("Sent encapsulated key")

        # Receive encrypted message
        enc_len = int.from_bytes(conn.recv(4), "big")
        encrypted = conn.recv(enc_len)
        print("Received encrypted message")

        # Decrypt
        message = decrypt_message(shared_secret[:32], encrypted)
        print(f"Decrypted message: {message}")
