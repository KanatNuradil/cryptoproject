// Blockchain Audit Ledger Implementation
// Module 4: Proof-of-Work Blockchain with Merkle Trees

const API_BASE = "/api/blockchain";

// Utility functions for SHA-256 hashing
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate ECDSA key pair for transaction signing
async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["sign", "verify"]
  );
  return keyPair;
}

// Sign transaction data
async function signTransaction(privateKey, data) {
  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" }
    },
    privateKey,
    new TextEncoder().encode(data)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// Verify transaction signature
async function verifyTransactionSignature(publicKey, data, signature) {
  try {
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    return await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" }
      },
      publicKey,
      signatureBytes,
      new TextEncoder().encode(data)
    );
  } catch {
    return false;
  }
}

// Merkle Tree Implementation
class MerkleTree {
  constructor(transactions) {
    this.transactions = transactions;
    this.tree = [];
    this.buildTree();
  }

  async buildTree() {
    // Create leaf nodes (transaction hashes)
    const leaves = [];
    for (const tx of this.transactions) {
      leaves.push(await sha256(tx));
    }

    this.tree = [leaves];

    // Build tree upwards
    while (this.tree[this.tree.length - 1].length > 1) {
      const currentLevel = this.tree[this.tree.length - 1];
      const nextLevel = [];

      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
        const combined = left + right;
        nextLevel.push(await sha256(combined));
      }

      this.tree.push(nextLevel);
    }
  }

  getRoot() {
    return this.tree.length > 0 ? this.tree[this.tree.length - 1][0] : null;
  }

  async getProof(transactionIndex) {
    if (transactionIndex >= this.transactions.length) {
      throw new Error('Transaction index out of bounds');
    }

    const proof = [];
    let level = 0;
    let index = transactionIndex;

    while (level < this.tree.length - 1) {
      const currentLevel = this.tree[level];
      const isLeft = index % 2 === 0;
      const siblingIndex = isLeft ? index + 1 : index - 1;

      if (siblingIndex < currentLevel.length) {
        proof.push({
          hash: currentLevel[siblingIndex],
          isLeft: !isLeft
        });
      } else {
        // For odd number of nodes, duplicate the last node
        proof.push({
          hash: currentLevel[index],
          isLeft: !isLeft
        });
      }

      index = Math.floor(index / 2);
      level++;
    }

    return proof;
  }

  async verifyProof(transactionHash, proof, root) {
    let currentHash = transactionHash;

    for (const { hash, isLeft } of proof) {
      const combined = isLeft ? hash + currentHash : currentHash + hash;
      currentHash = await sha256(combined);
    }

    return currentHash === root;
  }
}

// Transaction Structure with Signature Support
class Transaction {
  constructor(data, privateKey = null) {
    this.data = data;
    this.timestamp = Date.now();
    this.signature = null;
    this.publicKey = null;

    if (privateKey) {
      this.sign(privateKey);
    }
  }

  async sign(privateKey) {
    const dataToSign = this.data + this.timestamp;
    this.signature = await signTransaction(privateKey, dataToSign);
    // Export public key for verification
    const publicKey = await crypto.subtle.exportKey('spki', privateKey);
    this.publicKey = btoa(String.fromCharCode(...new Uint8Array(publicKey)));
  }

  async isValid() {
    if (!this.signature || !this.publicKey) {
      return false; // Unsigned transaction
    }

    try {
      const publicKey = await crypto.subtle.importKey(
        'spki',
        Uint8Array.from(atob(this.publicKey), c => c.charCodeAt(0)),
        {
          name: "ECDSA",
          namedCurve: "P-256"
        },
        true,
        ["verify"]
      );

      const dataToVerify = this.data + this.timestamp;
      return await verifyTransactionSignature(publicKey, dataToVerify, this.signature);
    } catch {
      return false;
    }
  }
}

// Block Structure
class Block {
  constructor(index, previousHash, transactions, difficulty, timestamp = null, nonce = 0) {
    this.index = index;
    this.previousHash = previousHash;
    this.transactions = transactions;
    this.difficulty = difficulty;
    this.timestamp = timestamp || Date.now();
    this.nonce = nonce;
    this.merkleRoot = null;
    this.hash = null;
  }

  async calculateMerkleRoot() {
    const merkleTree = new MerkleTree(this.transactions);
    await merkleTree.buildTree();
    this.merkleRoot = merkleTree.getRoot();
    return this.merkleRoot;
  }

  async calculateHash() {
    const data = this.index + this.previousHash + this.merkleRoot + this.timestamp + this.nonce;
    this.hash = await sha256(data);
    return this.hash;
  }

  async mineBlock() {
    await this.calculateMerkleRoot();
    const target = '0'.repeat(this.difficulty) + 'f'.repeat(64 - this.difficulty);

    while (true) {
      await this.calculateHash();
      if (this.hash < target) {
        break;
      }
      this.nonce++;
    }

    return this;
  }

  async isValid(previousBlock = null) {
    // Check if previous hash matches
    if (previousBlock && this.previousHash !== previousBlock.hash) {
      return false;
    }

    // Verify merkle root
    const calculatedMerkleRoot = await this.calculateMerkleRoot();
    if (this.merkleRoot !== calculatedMerkleRoot) {
      return false;
    }

    // Verify proof of work
    const target = '0'.repeat(this.difficulty) + 'f'.repeat(64 - this.difficulty);
    const calculatedHash = await this.calculateHash();
    if (calculatedHash !== this.hash || this.hash >= target) {
      return false;
    }

    return true;
  }
}

// Blockchain Implementation
class Blockchain {
  constructor() {
    this.chain = [];
    this.pendingTransactions = [];
    this.difficulty = 4;

    // Create genesis block
    this.createGenesisBlock();
  }

  async createGenesisBlock() {
    const genesisBlock = new Block(0, '0', ['Genesis Block'], this.difficulty);
    await genesisBlock.mineBlock();
    this.chain.push(genesisBlock);
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  async addBlock(transactions, difficulty) {
    const latestBlock = this.getLatestBlock();
    const newBlock = new Block(
      latestBlock.index + 1,
      latestBlock.hash,
      transactions,
      difficulty
    );

    await newBlock.mineBlock();
    this.chain.push(newBlock);
    return newBlock;
  }

  async isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      if (!(await currentBlock.isValid(previousBlock))) {
        return false;
      }
    }
    return true;
  }

  async getMerkleProof(transactionHash, blockIndex) {
    const block = this.chain[blockIndex];
    if (!block) {
      throw new Error('Block not found');
    }

    const transactionIndex = block.transactions.findIndex(tx => {
      // Find transaction by content (simplified - in real implementation, use hash)
      return tx === transactionHash;
    });

    if (transactionIndex === -1) {
      throw new Error('Transaction not found in block');
    }

    const merkleTree = new MerkleTree(block.transactions);
    const proof = await merkleTree.getProof(transactionIndex);
    return proof;
  }

  async verifyTransaction(transactionHash, blockIndex) {
    try {
      const block = this.chain[blockIndex];
      if (!block) {
        return { valid: false, reason: 'Block not found' };
      }

      const proof = await this.getMerkleProof(transactionHash, blockIndex);
      const merkleTree = new MerkleTree(block.transactions);
      const isValid = await merkleTree.verifyProof(transactionHash, proof, block.merkleRoot);

      return { valid: isValid, proof };
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }

  // Chain reorganization handling (longest chain rule)
  async resolveChainConflict(newChain) {
    if (newChain.length <= this.chain.length) {
      return false; // Keep current chain
    }

    // Validate the new chain
    let isValid = true;
    for (let i = 1; i < newChain.length && isValid; i++) {
      if (!(await newChain[i].isValid(newChain[i - 1]))) {
        isValid = false;
      }
    }

    if (!isValid) {
      return false; // Invalid chain
    }

    // Replace with the longer valid chain
    this.chain = [...newChain];
    showToast('Chain reorganized to longer valid chain', false);
    return true;
  }

  // Verify all transaction signatures in a block
  async verifyBlockSignatures(blockIndex) {
    const block = this.chain[blockIndex];
    if (!block) {
      return { valid: false, reason: 'Block not found' };
    }

    const results = [];
    for (const txData of block.transactions) {
      // Try to parse as signed transaction
      try {
        const tx = JSON.parse(txData);
        if (tx.data && tx.signature && tx.publicKey) {
          const transaction = Object.assign(new Transaction(), tx);
          const isValid = await transaction.isValid();
          results.push({
            data: tx.data,
            signatureValid: isValid
          });
        } else {
          // Unsigned transaction (legacy)
          results.push({
            data: txData,
            signatureValid: null // Not applicable
          });
        }
      } catch {
        // Not a JSON transaction, treat as unsigned
        results.push({
          data: txData,
          signatureValid: null
        });
      }
    }

    const allValid = results.every(r => r.signatureValid === null || r.signatureValid === true);
    return {
      valid: allValid,
      results
    };
  }
}

// Global blockchain instance
let blockchain = new Blockchain();

// DOM Elements
const createBlockForm = document.getElementById('create-block-form');
const transactionDataTextarea = document.getElementById('transaction-data');
const difficultyInput = document.getElementById('difficulty');
const blockchainDisplay = document.getElementById('blockchain-display');
const verifyTransactionForm = document.getElementById('verify-transaction-form');
const verifyTxHashInput = document.getElementById('verify-tx-hash');
const verifyBlockIndexInput = document.getElementById('verify-block-index');
const verificationResult = document.getElementById('verification-result');
const validateChainBtn = document.getElementById('validate-chain-btn');
const chainValidationResult = document.getElementById('chain-validation-result');
const toast = document.getElementById('toast');

// Utility functions
function showToast(message, isError = false) {
  toast.textContent = message;
  toast.classList.remove('hidden', 'error');
  if (isError) toast.classList.add('error');
  setTimeout(() => toast.classList.add('hidden'), 5000);
}

function renderBlockchain() {
  blockchainDisplay.innerHTML = '';

  blockchain.chain.forEach((block, index) => {
    const blockEl = document.createElement('div');
    blockEl.className = 'block';
    blockEl.innerHTML = `
      <h4>Block ${block.index}</h4>
      <div class="block-info">
        <p><strong>Hash:</strong> ${block.hash}</p>
        <p><strong>Previous Hash:</strong> ${block.previousHash}</p>
        <p><strong>Merkle Root:</strong> ${block.merkleRoot}</p>
        <p><strong>Timestamp:</strong> ${new Date(block.timestamp).toLocaleString()}</p>
        <p><strong>Nonce:</strong> ${block.nonce}</p>
        <p><strong>Difficulty:</strong> ${block.difficulty}</p>
        <p><strong>Transactions:</strong></p>
        <ul>
          ${block.transactions.map(tx => `<li>${tx}</li>`).join('')}
        </ul>
      </div>
    `;
    blockchainDisplay.appendChild(blockEl);
  });
}

// Event listeners
createBlockForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const transactionData = transactionDataTextarea.value.trim();
  if (!transactionData) {
    showToast('Please enter transaction data', true);
    return;
  }

  const transactions = transactionData.split('\n').filter(tx => tx.trim());
  const difficulty = parseInt(difficultyInput.value);

  if (transactions.length === 0) {
    showToast('Please enter at least one transaction', true);
    return;
  }

  try {
    showToast('Mining block... This may take a moment.');
    const newBlock = await blockchain.addBlock(transactions, difficulty);
    renderBlockchain();
    createBlockForm.reset();
    difficultyInput.value = '4';
    showToast(`Block ${newBlock.index} mined successfully!`);
  } catch (error) {
    showToast(`Failed to mine block: ${error.message}`, true);
  }
});

verifyTransactionForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const txHash = verifyTxHashInput.value.trim();
  const blockIndex = parseInt(verifyBlockIndexInput.value);

  if (!txHash) {
    showToast('Please enter transaction hash', true);
    return;
  }

  if (isNaN(blockIndex) || blockIndex < 0 || blockIndex >= blockchain.chain.length) {
    showToast('Please enter a valid block index', true);
    return;
  }

  try {
    const result = await blockchain.verifyTransaction(txHash, blockIndex);

    if (result.valid) {
      verificationResult.innerHTML = `
        <div class="success">
          <h4>✓ Transaction Verified</h4>
          <p>Transaction is included in block ${blockIndex}</p>
          <details>
            <summary>Merkle Proof</summary>
            <pre>${JSON.stringify(result.proof, null, 2)}</pre>
          </details>
        </div>
      `;
    } else {
      verificationResult.innerHTML = `
        <div class="error">
          <h4>✗ Transaction Not Verified</h4>
          <p>Reason: ${result.reason}</p>
        </div>
      `;
    }
  } catch (error) {
    verificationResult.innerHTML = `
      <div class="error">
        <h4>✗ Verification Failed</h4>
        <p>Error: ${error.message}</p>
      </div>
    `;
  }
});

validateChainBtn.addEventListener('click', async () => {
  try {
    const isValid = await blockchain.isChainValid();

    if (isValid) {
      chainValidationResult.innerHTML = `
        <div class="success">
          <h4>✓ Chain is Valid</h4>
          <p>All blocks are properly linked and validated</p>
        </div>
      `;
    } else {
      chainValidationResult.innerHTML = `
        <div class="error">
          <h4>✗ Chain is Invalid</h4>
          <p>Block validation failed - possible tampering detected</p>
        </div>
      `;
    }
  } catch (error) {
    chainValidationResult.innerHTML = `
      <div class="error">
        <h4>✗ Validation Failed</h4>
        <p>Error: ${error.message}</p>
      </div>
    `;
  }
});

// Initialize
renderBlockchain();
