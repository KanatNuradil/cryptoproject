# User Guide

## Welcome to Crypt

Crypt is a comprehensive cybersecurity platform that provides secure messaging, file encryption, and blockchain audit ledger functionality. This guide will help you get started with each module.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Secure Messaging](#secure-messaging)
3. [File Encryption](#file-encryption)
4. [Blockchain Audit Ledger](#blockchain-audit-ledger)
5. [Troubleshooting](#troubleshooting)
6. [Security Best Practices](#security-best-practices)

## Quick Start

### System Requirements
- Modern web browser (Chrome 90+, Firefox 88+, Safari 14+)
- Internet connection
- JavaScript enabled

### Installation & Setup

1. **Start the server:**
```bash
python -m secure_messaging.server
```

2. **Open your browser:**
```
http://localhost:8000
```

3. **Begin using the platform!**

## Secure Messaging

### Creating an Account

1. Navigate to the main page (`http://localhost:8000`)
2. Click **"Sign up"**
3. Fill in the registration form:
   - **Username**: Choose a unique username (3-30 characters)
   - **Email**: Valid email address for password recovery
   - **Password**: Must meet complexity requirements:
     - At least 8 characters long
     - One uppercase letter
     - One lowercase letter
     - One number
     - One special character (!@#$%^&* etc.)

4. Click **"Create Account"**

### Setting Up Two-Factor Authentication (Recommended)

1. After logging in, click **"Set up Two-Factor Authentication"**
2. Install an authenticator app (Google Authenticator, Authy, etc.)
3. Scan the QR code displayed
4. Enter the 6-digit code from your app
5. Click **"Done"**

### Sending Messages

1. Log in to your account
2. In the recipient dropdown, select a user
3. Type your message in the text area
4. Click **"Send"**

### Reading Messages

1. Messages appear automatically in your inbox
2. Each message shows:
   - Sender's username
   - Timestamp
   - Message content
   - Signature validation status

### Password Recovery

1. On the login page, click **"Forgot password?"**
2. Enter your registered email address
3. Check your email for a secure reset link
4. Follow the link and set a new password

### Group Messaging

1. Log in to your account
2. Scroll to the "Group message" section
3. Enter recipient usernames separated by commas
4. Type your message
5. Click **"Send to group"**

## File Encryption

### Encrypting Files

1. Navigate to `http://localhost:8000/file_encryption.html`
2. Click **"Choose File"** to select a file
3. Enter a strong password for encryption
4. Click **"Encrypt File"**
5. Download the encrypted `.encrypted` file

### Decrypting Files

1. On the same page, click **"Choose File"** in the decryption section
2. Select your encrypted `.encrypted` file
3. Enter the same password used for encryption
4. Click **"Decrypt File"**
5. Download your original file

### Security Notes

- **Remember your password**: Lost passwords cannot be recovered
- **File size limits**: Large files may take time to process
- **Secure storage**: Store encrypted files safely
- **Password strength**: Use unique, complex passwords

## Blockchain Audit Ledger

### Understanding the Interface

The blockchain module provides:
- **Block Creation**: Mine new blocks with transactions
- **Chain Visualization**: View the entire blockchain
- **Transaction Verification**: Verify transactions using Merkle proofs
- **Chain Validation**: Ensure blockchain integrity

### Creating Blocks

1. Navigate to `http://localhost:8000/blockchain.html`
2. In the "Create New Block" section:
   - Enter transactions (one per line)
   - Set difficulty level (1-6, higher = more secure but slower)
3. Click **"Mine Block"**

### Understanding Block Information

Each block displays:
- **Index**: Block number in the chain
- **Hash**: Unique block identifier
- **Previous Hash**: Links to the previous block
- **Merkle Root**: Summary of all transactions
- **Timestamp**: When the block was created
- **Nonce**: Proof-of-work solution
- **Difficulty**: Mining difficulty
- **Transactions**: List of transaction data

### Verifying Transactions

1. In the "Verify Transaction" section:
   - Enter the transaction content exactly as stored
   - Enter the block index containing the transaction
2. Click **"Verify"**

The system will show:
- Whether the transaction exists in the specified block
- Merkle proof verification details

### Validating Chain Integrity

1. Click **"Validate Entire Chain"**
2. The system checks:
   - Block hash validity
   - Previous hash linkages
   - Merkle root correctness
   - Proof-of-work verification

## Custom Cryptography Library

### Available Implementations

The platform includes hand-implemented cryptographic primitives:

#### Caesar Cipher with Cryptanalysis
```python
from custom_crypto.caesar import encrypt, decrypt, frequency_analysis

encrypted = encrypt("HELLO", 3)  # "KHOOR"
decrypted = decrypt(encrypted, 3)  # "HELLO"
key = frequency_analysis(encrypted)  # Attempts to break the cipher
```

#### Vigenère Cipher with Kasiski Examination
```python
from custom_crypto.vigenere import encrypt, decrypt, kasiski_examination, frequency_analysis

encrypted = encrypt("HELLO", "KEY")
key_length = kasiski_examination(encrypted)  # Analyze ciphertext patterns
key = frequency_analysis(encrypted, key_length)  # Break the cipher
```

#### Simplified SHA-256
```python
from custom_crypto.sha256 import hash

digest = hash("Hello World")
```

#### Merkle Tree Construction
```python
from custom_crypto.merkle import MerkleTree

tree = MerkleTree(["tx1", "tx2", "tx3"])
root = tree.get_root()
proof = tree.get_proof(0)  # Proof for first transaction
```

#### RSA Key Generation
```python
from custom_crypto.rsa import generate_keypair, encrypt, decrypt

public_key, private_key = generate_keypair(2048)
encrypted = encrypt(12345, public_key)
decrypted = decrypt(encrypted, private_key)
```

#### AES Key Expansion
```python
from custom_crypto.aes import key_expansion

expanded_keys = key_expansion(b"0123456789abcdef" * 2)
```

## Troubleshooting

### Common Issues

#### "Request failed" Error
**Cause**: Server not running or network issues
**Solution**:
1. Ensure the server is running: `python -m secure_messaging.server`
2. Check that port 8000 is available
3. Try refreshing the page

#### Login Issues
**Cause**: Incorrect credentials or TOTP setup
**Solutions**:
- Verify username and password
- Check if TOTP is enabled (enter 6-digit code)
- Try password reset if credentials are forgotten

#### File Encryption/Decryption Fails
**Cause**: Password mismatch or corrupted file
**Solutions**:
- Ensure you're using the exact same password
- Check that the file wasn't corrupted during transfer
- Try with a smaller test file first

#### Blockchain Mining Takes Too Long
**Cause**: High difficulty setting
**Solutions**:
- Lower the difficulty (1-2 for testing)
- Be patient - higher difficulty = more security
- Close other applications to free up CPU

#### Messages Not Appearing
**Cause**: Network issues or recipient offline
**Solutions**:
- Check your internet connection
- Refresh the page
- Verify recipient username is correct

### Performance Tips

#### For Large Files
- Use smaller files when testing encryption
- Close unnecessary browser tabs
- Ensure stable internet connection

#### For Blockchain Operations
- Start with difficulty level 2-3 for reasonable mining times
- Close CPU-intensive applications
- Use a modern browser with good JavaScript performance

#### For Messaging
- Keep message sizes reasonable (<10KB)
- Avoid sending too many messages rapidly
- Check your browser's developer console for errors

### Browser Compatibility

**Recommended Browsers:**
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

**Required Features:**
- JavaScript ES6+ support
- Web Cryptography API
- Modern TLS support

### Security Warnings

#### Never Share
- Your login credentials
- TOTP backup codes
- File encryption passwords
- Private cryptographic keys

#### Always Verify
- HTTPS connections (green lock icon)
- Website certificates
- File integrity after decryption
- Transaction signatures in blockchain

## Security Best Practices

### Password Management
- Use unique passwords for each service
- Enable two-factor authentication
- Use password managers
- Change passwords regularly
- Never reuse passwords from breaches

### File Security
- Encrypt sensitive files before storage
- Use strong, unique passwords for encryption
- Store encrypted files in secure locations
- Verify file integrity after decryption
- Keep backup copies of important files

### Communication Security
- Verify recipient identities
- Use end-to-end encrypted channels
- Be cautious with sensitive information
- Report suspicious messages
- Log out when finished

### Blockchain Usage
- Understand transaction verification
- Validate chain integrity regularly
- Keep mining difficulty appropriate for security needs
- Backup important blockchain data
- Monitor for unusual activity

### General Security
- Keep software updated
- Use antivirus protection
- Be aware of phishing attempts
- Use secure networks when possible
- Report security issues promptly

## API Reference

### REST Endpoints

#### Authentication
```
POST /api/register          # Register new user
POST /api/login            # User authentication
POST /api/logout           # End session
POST /api/forgot-password  # Initiate password reset
POST /api/reset-password   # Complete password reset
```

#### Messaging
```
GET  /api/users            # List all users
GET  /api/messages         # Get user inbox
POST /api/messages         # Send message
POST /api/group-messages   # Send group message
```

#### File Operations
```
POST /api/files/encrypt    # Encrypt uploaded file
POST /api/files/decrypt    # Decrypt uploaded file
```

#### Two-Factor Authentication
```
POST /api/totp/setup       # Setup TOTP
POST /api/totp/disable     # Disable TOTP
```

### Response Codes

- **200**: Success
- **400**: Bad Request (validation error)
- **401**: Unauthorized (authentication required)
- **404**: Not Found
- **500**: Internal Server Error

### Error Messages

Common error responses include:
- `"Password must be at least 8 characters long"`
- `"Invalid TOTP token"`
- `"User already exists"`
- `"Recipient not found"`
- `"Request failed"`

## Support

### Getting Help

1. **Check this guide** for common issues
2. **Review troubleshooting section** for error resolution
3. **Check browser console** for technical errors
4. **Verify server logs** for backend issues

### Reporting Issues

When reporting problems, include:
- Browser and version
- Operating system
- Steps to reproduce the issue
- Error messages (if any)
- Server log excerpts (if applicable)

### Feature Requests

To suggest new features:
- Describe the use case
- Explain the benefit
- Consider security implications
- Provide implementation suggestions

## Advanced Usage

### Command Line Interface

For advanced users, the system provides a CLI:

```bash
# Start CLI mode
python -m secure_messaging

# Available commands
register  # Create account
login     # Authenticate
send      # Send message
inbox     # Read messages
users     # List users
logout    # End session
quit      # Exit
```

### Configuration Options

Environment variables for customization:
```bash
# Server settings
HOST=0.0.0.0
PORT=8000

# Email configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Security settings
SECRET_KEY=your-secret-key
```

### Database Management

The system uses SQLite for data storage:
- Location: `data/app.db`
- Automatic schema migrations
- Backup regularly for data safety

## Conclusion

Crypt provides a comprehensive platform for secure communication and data protection. By following this guide and implementing security best practices, you can effectively use all modules while maintaining strong security posture.

Remember: Security is a process, not a product. Stay vigilant, keep systems updated, and follow best practices for ongoing protection.
