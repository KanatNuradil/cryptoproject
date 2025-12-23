# System Architecture

## Overview

Crypt is a modular cybersecurity platform built with a layered architecture that separates concerns between frontend presentation, backend business logic, data persistence, and cryptographic operations. The system implements multiple security modules while maintaining clean interfaces between components.

## System Components

### 1. Frontend Layer (Web Interface)

```
frontend/
├── index.html            # Secure messaging SPA
├── app.js               # Authentication & messaging logic
├── blockchain.html      # Blockchain interface
├── blockchain.js        # PoW blockchain implementation
├── file_encryption.html # File encryption UI
├── file_encryption.js   # File encryption/decryption logic
└── styles.css           # UI styling
```

**Responsibilities:**
- User interface rendering
- Client-side validation
- API communication
- Session management via HttpOnly cookies

### 2. Backend Layer (API & Business Logic)

```
secure_messaging/
├── server.py           # FastAPI application & routes
├── app.py             # Authentication & messaging services
├── crypto.py          # Cryptographic operations
├── db.py              # Data persistence layer
├── validation.py      # Password complexity validation
├── totp.py            # TOTP 2FA implementation
└── emailer.py         # SMTP integration
```

**Responsibilities:**
- HTTP request handling
- Business logic execution
- Session management
- Data validation
- Error handling

### 3. Data Layer (Persistence)

```
data/
└── app.db            # SQLite database
```

**Schema:**
```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    wrapped_keys TEXT NOT NULL,
    public_payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    email TEXT,
    totp_secret TEXT,
    reset_token TEXT,
    reset_token_expires_at TEXT
);

-- Messages table
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    ephemeral_pub TEXT NOT NULL,
    signature TEXT NOT NULL,
    hmac TEXT
);
```

### 4. Cryptography Layer (Custom Implementations)

```
custom_crypto/
├── caesar.py         # Classical cipher with cryptanalysis
├── vigenere.py       # Polyalphabetic cipher with breaking
├── sha256.py         # Hash function implementation
├── merkle.py         # Merkle tree construction
├── rsa.py            # Asymmetric cryptography
└── aes.py            # Symmetric key expansion
```

## Architecture Diagrams

### High-Level System Architecture

```
┌─────────────────┐    HTTP/HTTPS    ┌─────────────────┐
│                 │◄────────────────►│                 │
│   Web Browser   │                  │   FastAPI       │
│   (Frontend)    │                  │   Server        │
└─────────────────┘                  └─────────────────┘
                                           │
                                           │
                              ┌────────────▼────────────┐
                              │                         │
                              │   Business Logic       │
                              │   (Auth, Messaging)    │
                              └────────────▲────────────┘
                                           │
                                           │
                              ┌────────────▼────────────┐
                              │                         │
                              │   Cryptography Layer   │
                              │   (X25519, AES, etc.)  │
                              └────────────▲────────────┘
                                           │
                                           │
                              ┌────────────▼────────────┐
                              │                         │
                              │   Data Persistence     │
                              │   (SQLite)             │
                              └─────────────────────────┘
```

### Message Encryption Flow

```
Sender                     Network                    Receiver
  │                          │                          │
  │  Generate ephemeral      │                          │
  │  X25519 keypair          │                          │
  │  (x25519_priv, x25519_pub) │                        │
  │                          │                          │
  │  Derive shared secret    │                          │
  │  HKDF(X25519_ECDH(       │                          │
  │      x25519_priv,        │                          │
  │      recipient_pub))     │                          │
  │                          │                          │
  │  Split into AES + HMAC  │                          │
  │  keys for defense-in-   │                          │
  │  depth encryption        │                          │
  │                          │                          │
  │  Encrypt message:        │                          │
  │  AES-GCM(plaintext)      │                          │
  │  + HMAC-SHA256           │                          │
  │                          │                          │
  │  Sign envelope with      │                          │
  │  Ed25519 private key     │                          │
  └─────────────────────────►└─────────────────────────►
                             │                          │
                             │  Verify signature       │
                             │  with sender's Ed25519  │
                             │  public key             │
                             │                          │
                             │  Derive shared secret   │
                             │  HKDF(X25519_ECDH(      │
                             │      recipient_priv,     │
                             │      ephemeral_pub))     │
                             │                          │
                             │  Decrypt message:       │
                             │  AES-GCM + HMAC verify  │
                             └──────────────────────────┘
```

### Blockchain Architecture

```
Blockchain Structure:
┌─────────────────────────────────────────────────────┐
│                        Block N                      │
├─────────────────────────────────────────────────────┤
│ Index: N                                           │
│ Previous Hash: SHA256(Block N-1)                   │
│ Merkle Root: SHA256(Merkle Tree of Transactions)   │
│ Timestamp: Unix Timestamp                          │
│ Nonce: Mining Proof-of-Work                        │
│ Difficulty: Target Leading Zeros                   │
│ Transactions: [Tx1, Tx2, ..., TxM]                 │
│ Hash: SHA256(All Above Fields + Nonce) < Target    │
└─────────────────────────────────────────────────────┘
                              ▲
                              │
                    ┌─────────┴─────────┐
                    │                   │
            ┌───────▼───────┐   ┌───────▼───────┐
            │   Merkle      │   │   Transaction │
            │   Tree        │   │   Structure   │
            │               │   │               │
            ├───────────────┤   ├───────────────┤
            │ Root Hash     │   │ Data          │
            │ Left/Right    │   │ Timestamp     │
            │ Proofs        │   │ Signature     │
            │ Odd Handling  │   │ Public Key    │
            └───────────────┘   └───────────────┘
```

## Security Boundaries

### Trust Zones

1. **Client Zone** (Web Browser)
   - Handles user input validation
   - Manages UI state
   - No sensitive cryptographic keys

2. **Network Zone** (HTTP/HTTPS)
   - Encrypted with TLS 1.3 (in production)
   - Session cookies with HttpOnly/Secure flags
   - CORS policy restrictions

3. **Application Zone** (FastAPI Server)
   - Input validation and sanitization
   - Authentication and authorization
   - Business logic execution

4. **Data Zone** (SQLite Database)
   - Encrypted password hashes (bcrypt)
   - Wrapped private keys (PBKDF2)
   - Secure key storage

5. **Cryptographic Zone** (Crypto Libraries)
   - Key generation and management
   - Encryption/decryption operations
   - Digital signatures

### Data Flow Security

```
User Input → Input Validation → Authentication → Authorization → Business Logic → Cryptography → Database
     │             │                │             │             │             │             │
     └─────────────┼────────────────┼─────────────┼─────────────┼─────────────┼─────────────┘
                   │                │             │             │             │
            Reject invalid     Reject unauth   Reject unpriv   Sanitize      Encrypt       Audit
```

## Component Interfaces

### API Interface Design

```python
# FastAPI Route Structure
@app.post("/api/register")
async def register(payload: RegisterRequest) -> dict:
    """Register new user with validation"""
    # Input validation
    # Password complexity check
    # User creation
    # Response formatting

@app.post("/api/messages")
async def send_message(
    payload: MessageRequest,
    session: ActiveSession = Depends(get_current_session)
) -> dict:
    """Send encrypted message"""
    # Authentication check
    # Recipient validation
    # Message encryption
    # Database storage
    # Response formatting
```

### Service Layer Abstraction

```python
class AuthService:
    def __init__(self, database: Database):
        self.db = database

    def register(self, username: str, password: str, email: str = None) -> None:
        """User registration with security checks"""

    def login(self, username: str, password: str, totp_token: str = None) -> Tuple[ActiveSession, bool]:
        """Authentication with TOTP support"""

class MessagingService:
    def __init__(self, database: Database):
        self.db = database

    def send_message(self, session: ActiveSession, recipient: str, message: str) -> dict:
        """End-to-end encrypted message sending"""

    def inbox(self, session: ActiveSession) -> List[dict]:
        """Retrieve and decrypt messages"""
```

### Cryptographic Interface

```python
class CryptoOperations:
    @staticmethod
    def generate_user_secrets() -> Tuple[UserSecrets, dict]:
        """Generate X25519 and Ed25519 keypairs"""

    @staticmethod
    def derive_message_key(x25519_private: bytes, x25519_public: bytes) -> Tuple[bytes, bytes]:
        """Derive AES and HMAC keys from ECDH"""

    @staticmethod
    def encrypt_message(aes_key: bytes, plaintext: bytes, hmac_key: bytes) -> dict:
        """Encrypt message with AES-GCM + HMAC"""

    @staticmethod
    def decrypt_message(aes_key: bytes, encrypted_data: dict, hmac_key: bytes) -> bytes:
        """Decrypt and verify message integrity"""
```

## Scalability Considerations

### Horizontal Scaling
- Stateless API design allows load balancer distribution
- Session data in secure HttpOnly cookies
- Database connection pooling for multiple instances

### Vertical Scaling
- Efficient cryptographic operations (libsodium)
- Database query optimization
- Caching layer for public keys and user data

### Performance Optimizations
- Lazy loading of cryptographic keys
- Batch message processing
- Connection pooling for external services (SMTP)

## Deployment Architecture

### Development Environment
```
┌─────────────────┐
│   Local Machine │
├─────────────────┤
│ FastAPI (8000)  │
│ SQLite Database │
│ Local SMTP      │
└─────────────────┘
```

### Production Environment
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Application   │    │   Database      │
│   (nginx)       │────│   Servers       │────│   (PostgreSQL)  │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ SSL Termination │    │ FastAPI + Gunicorn │ │ Connection      │
│ Session Affinity│    │ Cryptography libs │ │ Pooling         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                              └────────────────────────┘
                                       │
                          ┌────────────▼────────────┐
                          │   Redis Cache          │
                          │   (Session/User Data)  │
                          └─────────────────────────┘
```

## Monitoring and Observability

### Logging Strategy
- Structured logging with correlation IDs
- Security event logging (failed auth attempts)
- Performance metrics (encryption/decryption times)
- Error tracking with stack traces

### Metrics Collection
- API response times
- Authentication success/failure rates
- Message encryption/decryption performance
- Database query performance

### Health Checks
- Database connectivity
- Cryptographic library availability
- External service dependencies (SMTP)
- Certificate expiration monitoring

## Future Extensibility

### Plugin Architecture
- Modular cryptographic backends
- Custom authentication providers
- Additional messaging protocols
- Blockchain consensus algorithms

### API Versioning
- Semantic versioning for API endpoints
- Backward compatibility maintenance
- Deprecation notices for old versions

### Microservice Decomposition
- Separate authentication service
- Message processing service
- File storage service
- Blockchain consensus service
