# PQVPN - Post-Quantum VPN

[![CI](https://github.com/tadaka9/PQVPN/actions/workflows/ci.yml/badge.svg)](https://github.com/tadaka9/PQVPN/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tadaka9/PQVPN/actions/workflows/codeql.yml/badge.svg)](https://github.com/tadaka9/PQVPN/actions/workflows/codeql.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Custom-blue.svg)](LICENSE)

**Path Quilt VPN** - A peer-to-peer free VPN for everyone, secured with post-quantum cryptography.

> ⚠️ **Warning**: This is a prototype/research project. Not intended for production use.

## 🌟 Features

- **Post-Quantum Cryptography**: Uses Kyber (ML-KEM) for key exchange, resistant to quantum computer attacks
- **Modern Encryption**: AES-256-GCM for symmetric encryption
- **P2P Architecture**: Decentralized peer-to-peer networking
- **Extensible Design**: Plugin system for custom functionality
- **Anti-DPI Traffic Obfuscation**: Helps bypass deep packet inspection
- **Onion Routing Support**: Multi-layer encryption for enhanced privacy

## 📋 Requirements

- Python 3.10 or higher
- liboqs 0.15.0 (for post-quantum cryptography)
- CMake and OpenSSL development libraries

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y cmake libssl-dev build-essential
```

**macOS:**
```bash
brew install cmake openssl
```

**Arch Linux:**
```bash
sudo pacman -S cmake openssl
```

## 🚀 Installation

### 1. Install liboqs

```bash
wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.15.0.tar.gz
tar xzf 0.15.0.tar.gz
cd liboqs-0.15.0
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build -j$(nproc)
sudo cmake --install build
sudo ldconfig  # Linux only
```

### 2. Install PQVPN

```bash
git clone https://github.com/tadaka9/PQVPN.git
cd PQVPN
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

## 💻 Usage

### Running the Server

```bash
python server.py
```

Or use the main entry point:
```bash
python src/main.py --mode server
```

### Running the Client

```bash
python client.py
```

Or:
```bash
python src/main.py --mode client --server <server-address>
```

## 🏗️ Architecture

### Core Components

- **Crypto Layer**: Post-quantum key exchange (Kyber) + AES-256-GCM encryption
- **Network Layer**: P2P networking with discovery protocol
- **Routing Layer**: Onion routing with multi-hop support
- **Transport Layer**: Anti-DPI traffic obfuscation
- **Plugin System**: Extensible architecture for custom features

### Key Exchange Flow

1. Client generates Kyber keypair (post-quantum secure)
2. Client sends public key to server
3. Server encapsulates symmetric key using client's public key
4. Server sends encapsulated key back to client
5. Client decapsulates to obtain shared symmetric key
6. Both use symmetric key for AES-256-GCM encryption

### Future Roadmap

- [ ] Dilithium signatures for authentication
- [ ] ChaCha20-Poly1305 cipher support
- [ ] Full onion routing implementation
- [ ] GUI client
- [ ] Mobile support (Android/iOS)
- [ ] NAT traversal improvements

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/pqvpn --cov-report=html

# Run specific test suite
pytest tests/test_crypto.py
```

### Manual Testing

Manual test scripts are available for specific features:
- `manual_test_bootstrap.py` - Bootstrap node testing
- `manual_test_onion.py` - Onion routing testing
- `manual_test_poisoning.py` - Route poisoning attack simulation
- `manual_test_traffic_anti_dpi.py` - DPI evasion testing

## 🛠️ Development

### Code Quality

```bash
# Linting
ruff check .

# Formatting
ruff format .

# Type checking (if configured)
mypy src/

# Security scanning
bandit -r src/
```

### Project Structure

```
PQVPN/
├── src/
│   ├── main.py           # Main entry point
│   └── pqvpn/            # Core package
│       ├── crypto/       # Cryptographic primitives
│       ├── network/      # Networking layer
│       ├── routing/      # Routing protocols
│       └── plugins/      # Plugin system
├── tests/                # Test suite
├── docs/                 # Documentation
├── benchmarks/           # Performance benchmarks
├── scripts/              # Utility scripts
├── client.py             # Simple client example
├── server.py             # Simple server example
└── pyproject.toml        # Project configuration
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔒 Security

This is a research prototype. For security concerns, please see [SECURITY.md](SECURITY.md).

**Known Limitations:**
- No formal security audit has been performed
- Implementation may have vulnerabilities
- Not recommended for sensitive production use

## 📄 License

See [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) for liboqs
- Post-quantum cryptography research community
- All contributors to this project

## 📚 Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber Algorithm](https://pq-crystals.org/kyber/)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)

## 👤 Author

**Davide Di Pino (dvx3)**
- GitHub: [@tadaka9](https://github.com/tadaka9)
- Website: [dvx3.online](https://dvx3.online/)

---

⭐ If you find this project interesting, please consider giving it a star!
