# PQVPN - Post-Quantum VPN Prototype

PQVPN is a prototype implementation of a VPN using post-quantum cryptography to ensure security against quantum computer attacks.

## Features

- Post-quantum key exchange using Kyber (ML-KEM)
- Symmetric encryption with AES-256-GCM
- Client-server architecture over TCP sockets

## Architecture

- **Client**: Generates Kyber keypair, sends public key to server, receives encapsulated symmetric key, uses it for encryption.
- **Server**: Receives client's public key, encapsulates a random symmetric key, sends back, uses the key for decryption.
- Future: Add Dilithium signatures for authentication, ChaCha20, etc.

## Requirements

- Python 3.8+
- cryptography
- liboqs-python

Install with: `pip install -r requirements.txt`

## Usage

1. Run the server: `python server.py`
2. Run the client: `python client.py`

## Project Structure

- `server.py`: Server script
- `client.py`: Client script
- `crypto.py`: Cryptographic functions (future modular)
- `README.md`: This file
- `requirements.txt`: Dependencies

## Notes

This is a basic prototype for demonstration. Not production-ready.