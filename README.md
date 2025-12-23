# Crypt

A comprehensive cybersecurity platform featuring end-to-end encrypted messaging, file encryption, and a proof-of-work blockchain audit ledger. This project implements multiple cryptographic primitives from scratch and provides a complete security toolkit.

## 🏗️ Architecture Overview

This application consists of four main modules:

1. **Secure Messaging System** - End-to-end encrypted messaging with TOTP 2FA
2. **File Encryption Module** - AES-256-GCM file encryption with PBKDF2 key derivation
3. **Blockchain Audit Ledger** - Proof-of-work blockchain with Merkle trees and transaction signatures
4. **Custom Cryptography Library** - Hand-implemented cryptographic primitives

## 📦 Project Structure

```
crypt/
├── secure_messaging/          # Backend API and CLI
│   ├── __init__.py
│   ├── __main__.py           # CLI entrypoint
│   ├── app.py                # Authentication & messaging services
│   ├── crypto.py             # Cryptographic operations
│   ├── db.py                 # SQLite database layer
│   ├── server.py             # FastAPI web server
│   ├── validation.py         # Password validation
│   ├── totp.py               # TOTP 2FA implementation
│   └── emailer.py            # SMTP email integration
├── frontend/                 # Web interface
│   ├── index.html            # Secure messaging UI
│   ├── app.js                # Frontend logic
│   ├── blockchain.html       # Blockchain interface
│   ├── blockchain.js         # Blockchain implementation
│   ├── file_encryption.html  # File encryption UI
│   ├── file_encryption.js    # File encryption logic
│   └── styles.css            # UI styling
├── docs/                     # Documentation
│   ├── architecture.md       # System design
│   ├── security_analysis.md  # Threat model
│   └── user_guide.md         # User manual
├── data/                     # Application data
│   └── app.db                # SQLite database
├── tests/                    # Test suite
│   ├── test_api.py
│   └── test_core.py
├── custom_crypto/            # Hand-implemented crypto
│   ├── __init__.py
│   ├── caesar.py             # Caesar cipher with frequency analysis
│   ├── vigenere.py           # Vigenère cipher with Kasiski examination
│   ├── sha256.py             # Simplified SHA-256 implementation
│   ├── merkle.py             # Merkle tree implementation
│   ├── rsa.py                # RSA key generation & operations
│   └── aes.py                # AES key expansion
└── requirements.txt
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Modern web browser with ES6 support

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/crypt.git
cd crypt
```

2. **Set up Python environment**
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. **Start the application**
```bash
python -m secure_messaging.server
```

4. **Open your browser**
```
http://localhost:8000
```

## 🔐 Security Features

### End-to-End Encrypted Messaging
- **X25519 ECDH** key exchange for forward secrecy
- **AES-256-GCM** message encryption with per-message keys
- **Ed25519** digital signatures for authenticity
- **TOTP 2FA** with QR code setup
- **Secure password reset** with token-based flow

### File Encryption
- **AES-256-GCM** encryption with integrity verification
- **PBKDF2** key derivation from passwords
- **SHA-256** file hashing for tamper detection
- **Base64 encoding** for safe transport

### Blockchain Audit Ledger
- **Proof-of-work** consensus with adjustable difficulty
- **Merkle trees** for efficient transaction verification
- **ECDSA transaction signatures** for authenticity
- **Chain reorganization** handling (longest chain rule)

### Custom Cryptography (From Scratch)
- **Caesar cipher** with frequency analysis breaker
- **Vigenère cipher** with Kasiski examination
- **Simplified SHA-256** hash function
- **Merkle tree** construction and proofs
- **RSA key generation** with prime finding
- **AES key expansion** algorithm

## 🎯 Module Usage

### 1. Secure Messaging

**Web Interface:**
- Navigate to `http://localhost:8000`
- Register with strong password
- Set up TOTP 2FA (optional)
- Send/receive encrypted messages

**CLI Usage:**
```bash
# Register user
python -m secure_messaging register

# Login
python -m secure_messaging login

# Send message
python -m secure_messaging send
```

### 2. File Encryption

**Web Interface:**
- Navigate to `http://localhost:8000/file_encryption.html`
- Choose file and enter password
- Download encrypted file
- Upload and decrypt with same password

### 3. Blockchain Audit Ledger

**Web Interface:**
- Navigate to `http://localhost:8000/blockchain.html`
- Create blocks with transactions
- Verify transaction inclusion with Merkle proofs
- Validate chain integrity

### 4. Custom Cryptography

**Python API:**
```python
from custom_crypto import caesar, vigenere, sha256, merkle, rsa, aes

# Caesar cipher with frequency analysis
encrypted = caesar.encrypt("HELLO", 3)
decrypted = caesar.decrypt(encrypted, 3)
key = caesar.frequency_analysis(encrypted)  # Break cipher

# Vigenère cipher with Kasiski examination
encrypted = vigenere.encrypt("HELLO", "KEY")
key_length = vigenere.kasiski_examination(encrypted)
key = vigenere.frequency_analysis(encrypted, key_length)

# SHA-256 implementation
hash_value = sha256.hash("Hello World")

# Merkle tree
tree = merkle.MerkleTree(["tx1", "tx2", "tx3"])
root = tree.get_root()
proof = tree.get_proof(0)

# RSA operations
public_key, private_key = rsa.generate_keypair(2048)
encrypted = rsa.encrypt(123, public_key)
decrypted = rsa.decrypt(encrypted, private_key)

# AES key expansion
expanded_keys = aes.key_expansion(b"0123456789abcdef" * 2)
```

## 🔍 API Endpoints

### Authentication
```
POST /api/register          # User registration
POST /api/login            # User login with TOTP support
POST /api/logout           # Session logout
POST /api/forgot-password  # Password reset initiation
POST /api/reset-password   # Password reset completion
```

### Messaging
```
GET  /api/users            # List users
GET  /api/messages         # Get inbox
POST /api/messages         # Send message
POST /api/group-messages   # Send group message
```

### File Operations
```
POST /api/files/encrypt    # Encrypt file
POST /api/files/decrypt    # Decrypt file
```

### TOTP Management
```
POST /api/totp/setup       # Setup 2FA
POST /api/totp/disable     # Disable 2FA
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=secure_messaging tests/

# Run specific test
pytest tests/test_api.py::test_register_new_user
```

## 📚 Documentation

- **[User Guide](docs/user_guide.md)** - How to use each module
- **[Architecture](docs/architecture.md)** - System design and diagrams
- **[Security Analysis](docs/security_analysis.md)** - Threat model and mitigations

## 🔧 Configuration

### Environment Variables
```bash
# SMTP Configuration (for password reset)
export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"

# Server Configuration
export HOST="0.0.0.0"
export PORT="8000"
```

### Production Deployment
```bash
# Enable HTTPS
uvicorn secure_messaging.server:app --ssl-keyfile key.pem --ssl-certfile cert.pem

# Use production database
export DATABASE_URL="postgresql://user:pass@localhost/crypt"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team

| Name | Role | Responsibilities |
|------|------|------------------|
| Didar Nurdaulet | Cryptography & Messaging Lead | Implement core crypto library, Design and implement messaging module |
| Sherkhan Kudaibergen | Authentication & Security Lead | Design and implement authentication module, ensure secure coding practices across project |
| Nuradil Kanat |  Blockchain & Integration Lead | Design and implement blockchain module, integrate all modules together |

## 🙏 Acknowledgments

- Built with FastAPI, cryptography, and modern web technologies
- Implements multiple cryptographic standards and best practices
- Educational platform for learning applied cryptography
