#!/usr/bin/env python3

import os
import socket

import oqs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = 'localhost'
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
    s.connect((HOST, PORT))
    print("Connected to server")
    
    # Generate keypair
    kem = oqs.KeyEncapsulation('Kyber1024')
    pk, sk = kem.generate_keypair()
    print("Generated Kyber keypair")
    
    # Send public key
    s.send(len(pk).to_bytes(4, 'big'))
    s.send(pk)
    print("Sent public key")
    
    # Receive ciphertext
    ct_len = int.from_bytes(s.recv(4), 'big')
    ciphertext = s.recv(ct_len)
    print("Received encapsulated key")
    
    # Decapsulate
    shared_secret = kem.decap_secret(ciphertext, sk)
    print("Decapsulated shared secret")
    
    # Encrypt message
    message = "Hello from PQVPN client!"
    encrypted = encrypt_message(shared_secret[:32], message)
    print("Encrypted message")
    
    # Send encrypted message
    s.send(len(encrypted).to_bytes(4, 'big'))
    s.send(encrypted)
    print("Sent encrypted message")