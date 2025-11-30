#!/usr/bin/env python3
"""
CRYPTOGRAPHY & HASHING DEEP DIVE
A comprehensive exploration of modern cryptographic primitives in Python 3

Topics covered:
1. Hash Functions (SHA, BLAKE2/3, collision resistance)
2. Password Hashing (bcrypt, Argon2, scrypt)
3. Symmetric Encryption (AES-GCM, ChaCha20-Poly1305)
4. Asymmetric Encryption (RSA, Elliptic Curves)
5. Key Derivation Functions (PBKDF2, HKDF, scrypt)
6. MACs and Digital Signatures
7. Advanced: Merkle Trees, Shamir's Secret Sharing
"""

import hashlib
import hmac
import secrets
import os
import time
from typing import List, Tuple
from functools import reduce

# Third-party crypto libraries
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1, SECP384R1
from cryptography.hazmat.backends import default_backend

import argon2
import blake3
import nacl.secret
import nacl.utils
import nacl.pwhash
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey


def banner(title: str):
    """Pretty section banner"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def hex_preview(data: bytes, n: int = 32) -> str:
    """Show first n bytes as hex"""
    return data[:n].hex() + ("..." if len(data) > n else "")


# =============================================================================
# SECTION 1: HASH FUNCTIONS
# =============================================================================

def explore_hash_functions():
    banner("1. HASH FUNCTIONS - The Foundation")
    
    test_data = b"The quick brown fox jumps over the lazy dog"
    
    print("Input:", test_data.decode())
    print(f"Length: {len(test_data)} bytes\n")
    
    # Standard library hashes
    print("--- Standard Library (hashlib) ---")
    
    algos = ['md5', 'sha1', 'sha256', 'sha384', 'sha512', 
             'sha3_256', 'sha3_512', 'blake2b', 'blake2s']
    
    for algo in algos:
        h = hashlib.new(algo, test_data)
        print(f"{algo:12} ({h.digest_size*8:3} bits): {h.hexdigest()[:48]}...")
    
    # BLAKE3 - the new hotness
    print("\n--- BLAKE3 (modern, fast, parallelizable) ---")
    b3_hash = blake3.blake3(test_data)
    print(f"blake3       (256 bits): {b3_hash.hexdigest()}")
    
    # BLAKE3 with extended output (XOF - eXtendable Output Function)
    b3_xof = blake3.blake3(test_data)
    print(f"blake3 (512 bits XOF) : {b3_xof.hexdigest(length=64)}")
    
    # Demonstrate avalanche effect
    print("\n--- Avalanche Effect Demo ---")
    original = b"Hello World"
    modified = b"Hello World!"  # Just one character added
    
    h1 = hashlib.sha256(original).hexdigest()
    h2 = hashlib.sha256(modified).hexdigest()
    
    print(f"Original: {original.decode():20} -> {h1}")
    print(f"Modified: {modified.decode():20} -> {h2}")
    
    # Count bit differences
    bits_diff = bin(int(h1, 16) ^ int(h2, 16)).count('1')
    print(f"Bit difference: {bits_diff}/256 ({bits_diff/256*100:.1f}%) - should be ~50%")
    
    # Hash collision probability (Birthday paradox)
    print("\n--- Birthday Paradox / Collision Probability ---")
    print("For n-bit hash, expect collision after ~2^(n/2) hashes:")
    print("  MD5 (128-bit):    ~2^64   = ~18 quintillion (BROKEN!)")
    print("  SHA-1 (160-bit):  ~2^80   (BROKEN! SHAttered attack)")
    print("  SHA-256 (256-bit): ~2^128 = ~340 undecillion")
    print("  SHA-512 (512-bit): ~2^256 (heat death of universe)")


# =============================================================================
# SECTION 2: PASSWORD HASHING
# =============================================================================

def explore_password_hashing():
    banner("2. PASSWORD HASHING - Slow by Design")
    
    password = b"correct horse battery staple"
    
    print("Password:", password.decode())
    print("\n  NEVER use fast hashes (MD5/SHA) for passwords!")
    print("   Reason: GPUs can compute billions of SHA256/sec\n")
    
    # Argon2 - winner of Password Hashing Competition (2015)
    print("--- Argon2id (PHC Winner, recommended) ---")
    
    # Using argon2-cffi
    ph = argon2.PasswordHasher(
        time_cost=3,        # iterations
        memory_cost=65536,  # 64 MB
        parallelism=4,      # threads
        hash_len=32,
        salt_len=16,
        type=argon2.Type.ID  # Argon2id - hybrid of Argon2i and Argon2d
    )
    
    start = time.perf_counter()
    argon2_hash = ph.hash(password.decode())
    elapsed = time.perf_counter() - start
    
    print(f"Hash: {argon2_hash[:60]}...")
    print(f"Time: {elapsed*1000:.1f}ms")
    print(f"Verify: {ph.verify(argon2_hash, password.decode())}")
    
    # Using PyNaCl's Argon2
    print("\n--- PyNaCl Argon2id ---")
    start = time.perf_counter()
    nacl_hash = nacl.pwhash.argon2id.str(password)
    elapsed = time.perf_counter() - start
    print(f"Hash: {nacl_hash[:60]}...")
    print(f"Time: {elapsed*1000:.1f}ms")
    
    # Scrypt
    print("\n--- scrypt (memory-hard, used by Litecoin) ---")
    salt = os.urandom(16)
    
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,  # CPU/memory cost (must be power of 2)
        r=8,      # block size
        p=1       # parallelization
    )
    
    start = time.perf_counter()
    scrypt_key = kdf.derive(password)
    elapsed = time.perf_counter() - start
    
    print(f"Derived key: {scrypt_key.hex()}")
    print(f"Salt: {salt.hex()}")
    print(f"Time: {elapsed*1000:.1f}ms")
    
    # PBKDF2 - older but still acceptable with high iterations
    print("\n--- PBKDF2-HMAC-SHA256 (older, CPU-only) ---")
    salt = os.urandom(16)
    iterations = 600_000  # OWASP recommends 600k+ for SHA256
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    
    start = time.perf_counter()
    pbkdf2_key = kdf.derive(password)
    elapsed = time.perf_counter() - start
    
    print(f"Derived key: {pbkdf2_key.hex()}")
    print(f"Iterations: {iterations:,}")
    print(f"Time: {elapsed*1000:.1f}ms")
    
    print("\n Recommendation hierarchy:")
    print("   1. Argon2id (best, memory-hard + side-channel resistant)")
    print("   2. scrypt (good, memory-hard)")
    print("   3. bcrypt (acceptable, but 72-byte limit)")
    print("   4. PBKDF2-SHA256 (last resort, 600k+ iterations)")


# =============================================================================
# SECTION 3: SYMMETRIC ENCRYPTION
# =============================================================================

def explore_symmetric_encryption():
    banner("3. SYMMETRIC ENCRYPTION - AES & ChaCha20")
    
    plaintext = b"Attack at dawn! Bring pizza."
    
    print(f"Plaintext: {plaintext.decode()}")
    print(f"Length: {len(plaintext)} bytes\n")
    
    # AES-256-GCM (Authenticated Encryption with Associated Data)
    print("--- AES-256-GCM (AEAD) ---")
    
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aad = b"metadata-not-encrypted-but-authenticated"
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    print(f"Key (256-bit):  {key.hex()}")
    print(f"Nonce (96-bit): {nonce.hex()}")
    print(f"AAD: {aad.decode()}")
    print(f"Ciphertext+Tag: {ciphertext.hex()}")
    print(f"  └─ Ciphertext: {ciphertext[:-16].hex()}")
    print(f"  └─ Auth Tag:   {ciphertext[-16:].hex()}")
    
    # Decrypt
    decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
    print(f"Decrypted: {decrypted.decode()}")
    
    # ChaCha20-Poly1305 (alternative to AES, no timing attacks)
    print("\n--- ChaCha20-Poly1305 (AEAD, constant-time) ---")
    
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)  # 96-bit nonce
    
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    
    print(f"Key (256-bit):  {key.hex()}")
    print(f"Nonce (96-bit): {nonce.hex()}")
    print(f"Ciphertext+Tag: {ciphertext.hex()}")
    
    decrypted = chacha.decrypt(nonce, ciphertext, aad)
    print(f"Decrypted: {decrypted.decode()}")
    
    # PyNaCl SecretBox (XSalsa20-Poly1305)
    print("\n--- NaCl SecretBox (XSalsa20-Poly1305) ---")
    
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(key)
    
    # Nonce generated automatically
    encrypted = box.encrypt(plaintext)
    
    print(f"Key (256-bit): {key.hex()}")
    print(f"Nonce (192-bit): {encrypted.nonce.hex()}")
    print(f"Ciphertext: {encrypted.ciphertext.hex()}")
    
    decrypted = box.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode()}")
    
    print("\n CRITICAL: Never reuse (key, nonce) pairs!")
    print("   - GCM: nonce reuse = catastrophic auth tag forgery")
    print("   - ChaCha20-Poly1305: nonce reuse = key recovery possible")


# =============================================================================
# SECTION 4: ASYMMETRIC ENCRYPTION
# =============================================================================

def explore_asymmetric_encryption():
    banner("4. ASYMMETRIC ENCRYPTION - RSA & Elliptic Curves")
    
    message = b"Secret message for Bob"
    
    # RSA Encryption
    print("--- RSA-2048 with OAEP padding ---")
    
    # Generate keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print(f"Private key (first 64 chars): {private_pem[:64].decode()}...")
    print(f"Public key (first 64 chars):  {public_pem[:64].decode()}...")
    
    # Encrypt with public key
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"\nPlaintext:  {message.decode()}")
    print(f"Ciphertext: {ciphertext.hex()[:64]}...")
    
    # Decrypt with private key
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Decrypted:  {decrypted.decode()}")
    
    # X25519 Key Exchange (Elliptic Curve Diffie-Hellman)
    print("\n--- X25519 ECDH Key Exchange ---")
    
    # Alice generates her keypair
    alice_private = x25519.X25519PrivateKey.generate()
    alice_public = alice_private.public_key()
    
    # Bob generates his keypair
    bob_private = x25519.X25519PrivateKey.generate()
    bob_public = bob_private.public_key()
    
    # Key exchange - both derive the same shared secret!
    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)
    
    print(f"Alice's public: {alice_public.public_bytes_raw().hex()}")
    print(f"Bob's public:   {bob_public.public_bytes_raw().hex()}")
    print(f"Alice's shared: {alice_shared.hex()}")
    print(f"Bob's shared:   {bob_shared.hex()}")
    print(f"Match: {alice_shared == bob_shared}")
    
    # PyNaCl Box (X25519 + XSalsa20-Poly1305)
    print("\n--- NaCl Box (Authenticated Public-Key Encryption) ---")
    
    # Alice and Bob generate keypairs
    alice_sk = PrivateKey.generate()
    alice_pk = alice_sk.public_key
    
    bob_sk = PrivateKey.generate()
    bob_pk = bob_sk.public_key
    
    # Alice encrypts to Bob
    alice_box = Box(alice_sk, bob_pk)
    encrypted = alice_box.encrypt(message)
    
    print(f"Alice -> Bob encrypted: {encrypted.ciphertext.hex()[:32]}...")
    
    # Bob decrypts from Alice
    bob_box = Box(bob_sk, alice_pk)
    decrypted = bob_box.decrypt(encrypted)
    
    print(f"Bob decrypted: {decrypted.decode()}")
    
    print("\n RSA vs ECC comparison:")
    print("   RSA-2048  ≈ ECDSA P-256 ≈ 128-bit security")
    print("   RSA-3072  ≈ ECDSA P-384 ≈ 192-bit security")
    print("   RSA-15360 ≈ ECDSA P-521 ≈ 256-bit security")
    print("   X25519/Ed25519: ~128-bit security, very fast")


# =============================================================================
# SECTION 5: KEY DERIVATION FUNCTIONS
# =============================================================================

def explore_key_derivation():
    banner("5. KEY DERIVATION FUNCTIONS")
    
    # Derive encryption keys from a master secret
    master_secret = os.urandom(32)
    
    print(f"Master secret: {master_secret.hex()}\n")
    
    # HKDF - HMAC-based Key Derivation Function
    print("--- HKDF (extract-then-expand) ---")
    
    # HKDF is great for deriving multiple keys from one secret
    salt = os.urandom(16)  # Can be None
    info_enc = b"encryption-key"
    info_mac = b"mac-key"
    
    hkdf_enc = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info_enc,
    )
    
    hkdf_mac = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info_mac,
    )
    
    encryption_key = hkdf_enc.derive(master_secret)
    mac_key = hkdf_mac.derive(master_secret)
    
    print(f"Salt: {salt.hex()}")
    print(f"Encryption key (info='{info_enc.decode()}'): {encryption_key.hex()}")
    print(f"MAC key (info='{info_mac.decode()}'):        {mac_key.hex()}")
    
    # Key stretching example
    print("\n--- Key Stretching for weak passwords ---")
    
    weak_password = b"password123"
    salt = os.urandom(16)
    
    # Using scrypt for key stretching
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    stretched_key = kdf.derive(weak_password)
    
    print(f"Weak password: {weak_password.decode()}")
    print(f"Stretched key: {stretched_key.hex()}")
    print("Note: Takes ~1 second, making brute-force expensive")


# =============================================================================
# SECTION 6: MACs AND DIGITAL SIGNATURES
# =============================================================================

def explore_macs_and_signatures():
    banner("6. MACs & DIGITAL SIGNATURES")
    
    message = b"Transfer $1000000 to account 12345"
    
    # HMAC
    print("--- HMAC (Symmetric Authentication) ---")
    
    key = secrets.token_bytes(32)
    
    mac = hmac.new(key, message, hashlib.sha256).digest()
    
    print(f"Message: {message.decode()}")
    print(f"Key: {key.hex()}")
    print(f"HMAC-SHA256: {mac.hex()}")
    
    # Verify
    expected = hmac.new(key, message, hashlib.sha256).digest()
    is_valid = hmac.compare_digest(mac, expected)  # Constant-time comparison!
    print(f"Valid: {is_valid}")
    
    # Ed25519 Signatures
    print("\n--- Ed25519 Digital Signatures ---")
    
    # Using cryptography library
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    signature = private_key.sign(message)
    
    print(f"Private key: {private_key.private_bytes_raw().hex()}")
    print(f"Public key:  {public_key.public_bytes_raw().hex()}")
    print(f"Signature:   {signature.hex()}")
    
    # Verify
    try:
        public_key.verify(signature, message)
        print("Signature valid: True")
    except Exception:
        print("Signature valid: False")
    
    # PyNaCl signing
    print("\n--- PyNaCl Ed25519 Signing ---")
    
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    signed = signing_key.sign(message)
    
    print(f"Signing key:   {signing_key.encode().hex()}")
    print(f"Verify key:    {verify_key.encode().hex()}")
    print(f"Signature:     {signed.signature.hex()}")
    
    # Verify
    try:
        verify_key.verify(signed)
        print("Signature valid: True")
    except Exception:
        print("Signature valid: False")
    
    # ECDSA with secp256k1 (Bitcoin curve)
    print("\n--- ECDSA secp256k1 (Bitcoin/Ethereum curve) ---")
    
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    
    private_key = ec.generate_private_key(SECP256K1())
    public_key = private_key.public_key()
    
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    # Decode signature to (r, s) format
    r, s = decode_dss_signature(signature)
    
    print(f"Message hash: {hashlib.sha256(message).hexdigest()}")
    print(f"Signature r:  {hex(r)}")
    print(f"Signature s:  {hex(s)}")
    
    # Verify
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("Signature valid: True")
    except Exception:
        print("Signature valid: False")
    
    print("\n HMAC vs Digital Signatures:")
    print("   HMAC: Both parties share secret key (can both create MACs)")
    print("   Signatures: Only private key holder can sign (non-repudiation)")


# =============================================================================
# SECTION 7: ADVANCED - MERKLE TREES
# =============================================================================

def explore_merkle_trees():
    banner("7. MERKLE TREES - Blockchain Foundation")
    
    # Transaction data (like Bitcoin)
    transactions = [
        b"Alice -> Bob: 5 BTC",
        b"Bob -> Charlie: 2 BTC",
        b"Charlie -> Dave: 1 BTC",
        b"Dave -> Eve: 0.5 BTC",
        b"Eve -> Alice: 0.25 BTC",
        b"Frank -> Grace: 3 BTC",
        b"Grace -> Heidi: 1.5 BTC",
        b"Heidi -> Ivan: 0.75 BTC",
    ]
    
    def hash_node(data: bytes) -> bytes:
        """Double SHA256 (like Bitcoin)"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def build_merkle_tree(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
        """Build Merkle tree and return root + all levels"""
        if not leaves:
            return b'\x00' * 32, []
        
        # Hash all leaves
        current_level = [hash_node(leaf) for leaf in leaves]
        levels = [current_level.copy()]
        
        # Build tree bottom-up
        while len(current_level) > 1:
            # Duplicate last element if odd number
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])
            
            # Combine pairs
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                next_level.append(hash_node(combined))
            
            current_level = next_level
            levels.append(current_level.copy())
        
        return current_level[0], levels
    
    def get_merkle_proof(index: int, levels: List[List[bytes]]) -> List[Tuple[bytes, str]]:
        """Get proof for leaf at index"""
        proof = []
        for level in levels[:-1]:
            # Determine sibling
            if index % 2 == 0:
                sibling_idx = index + 1 if index + 1 < len(level) else index
                direction = 'right'
            else:
                sibling_idx = index - 1
                direction = 'left'
            
            proof.append((level[sibling_idx], direction))
            index //= 2
        
        return proof
    
    def verify_merkle_proof(leaf: bytes, proof: List[Tuple[bytes, str]], root: bytes) -> bool:
        """Verify a Merkle proof"""
        current = hash_node(leaf)
        
        for sibling, direction in proof:
            if direction == 'left':
                current = hash_node(sibling + current)
            else:
                current = hash_node(current + sibling)
        
        return current == root
    
    # Build the tree
    merkle_root, levels = build_merkle_tree(transactions)
    
    print("Transactions:")
    for i, tx in enumerate(transactions):
        leaf_hash = hash_node(tx)
        print(f"  [{i}] {tx.decode():30} -> {leaf_hash.hex()[:16]}...")
    
    print(f"\nMerkle Tree Levels:")
    for i, level in enumerate(levels):
        print(f"  Level {i}: {len(level)} nodes")
        for j, node in enumerate(level):
            print(f"    [{j}] {node.hex()[:24]}...")
    
    print(f"\n Merkle Root: {merkle_root.hex()}")
    
    # Generate and verify proof for transaction 2
    proof_idx = 2
    proof = get_merkle_proof(proof_idx, levels)
    
    print(f"\nMerkle Proof for tx[{proof_idx}]: '{transactions[proof_idx].decode()}'")
    print("  Proof path:")
    for sibling, direction in proof:
        print(f"    + {direction:5}: {sibling.hex()[:24]}...")
    
    is_valid = verify_merkle_proof(transactions[proof_idx], proof, merkle_root)
    print(f"  Proof valid: {is_valid}")
    
    print("\n Merkle Tree Properties:")
    print(f"   Transactions: {len(transactions)}")
    print(f"   Tree depth:   {len(levels)}")
    print(f"   Proof size:   {len(proof)} hashes ({len(proof) * 32} bytes)")
    print(f"   Efficiency:   O(log n) proof vs O(n) full verification")


# =============================================================================
# SECTION 8: ADVANCED - SHAMIR'S SECRET SHARING
# =============================================================================

def explore_shamirs_secret_sharing():
    banner("8. SHAMIR'S SECRET SHARING - (k,n) Threshold Scheme")
    
    # We'll implement Shamir's Secret Sharing over a finite field
    # Using a 256-bit prime for security
    
    # Large prime (close to 2^256)
    PRIME = 2**256 - 189  # A known 256-bit prime
    
    def mod_inverse(a: int, m: int) -> int:
        """Extended Euclidean Algorithm for modular inverse"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m
    
    def generate_shares(secret: int, k: int, n: int, prime: int = PRIME) -> List[Tuple[int, int]]:
        """
        Generate n shares where any k can reconstruct the secret.
        Uses polynomial of degree k-1 where f(0) = secret.
        """
        # Generate random coefficients for polynomial
        # f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        coefficients = [secret] + [secrets.randbelow(prime) for _ in range(k - 1)]
        
        # Evaluate polynomial at points 1, 2, ..., n
        shares = []
        for x in range(1, n + 1):
            y = 0
            for i, coef in enumerate(coefficients):
                y = (y + coef * pow(x, i, prime)) % prime
            shares.append((x, y))
        
        return shares
    
    def reconstruct_secret(shares: List[Tuple[int, int]], prime: int = PRIME) -> int:
        """
        Reconstruct secret using Lagrange interpolation.
        """
        k = len(shares)
        secret = 0
        
        for i, (xi, yi) in enumerate(shares):
            # Calculate Lagrange basis polynomial L_i(0)
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator = (numerator * (-xj)) % prime
                    denominator = (denominator * (xi - xj)) % prime
            
            # L_i(0) = numerator / denominator
            lagrange = (numerator * mod_inverse(denominator, prime)) % prime
            
            # Add contribution: yi * L_i(0)
            secret = (secret + yi * lagrange) % prime
        
        return secret
    
    # Demo
    original_secret = int.from_bytes(os.urandom(32), 'big') % PRIME
    k = 3  # Threshold
    n = 5  # Total shares
    
    print(f"Original secret: {hex(original_secret)[:32]}...")
    print(f"Scheme: ({k}, {n}) - need {k} of {n} shares to reconstruct\n")
    
    # Generate shares
    shares = generate_shares(original_secret, k, n)
    
    print("Generated shares:")
    for i, (x, y) in enumerate(shares):
        print(f"  Share {i+1} (x={x}): {hex(y)[:32]}...")
    
    # Reconstruct with exactly k shares
    print(f"\nReconstruction with {k} shares (1, 3, 5):")
    subset = [shares[0], shares[2], shares[4]]
    recovered = reconstruct_secret(subset)
    print(f"  Recovered: {hex(recovered)[:32]}...")
    print(f"  Match: {recovered == original_secret}")
    
    # Try with different subset
    print(f"\nReconstruction with different {k} shares (2, 3, 4):")
    subset2 = [shares[1], shares[2], shares[3]]
    recovered2 = reconstruct_secret(subset2)
    print(f"  Recovered: {hex(recovered2)[:32]}...")
    print(f"  Match: {recovered2 == original_secret}")
    
    # Show that k-1 shares reveal nothing
    print(f"\n⚠️  With only {k-1} shares, NO information about secret is revealed!")
    print("   (This is information-theoretic security, not computational)")
    
    print("\n📊 Use cases:")
    print("   - Cryptocurrency wallet backup (2-of-3 shares)")
    print("   - Corporate key escrow (3-of-5 executives)")
    print("   - Distributed key management")


# =============================================================================
# SECTION 9: TIMING ATTACK DEMO
# =============================================================================

def explore_timing_attacks():
    banner("9. TIMING ATTACKS & CONSTANT-TIME COMPARISONS")
    
    correct_token = b"super_secret_api_token_12345"
    
    def vulnerable_compare(a: bytes, b: bytes) -> bool:
        """VULNERABLE: Early return reveals length of matching prefix"""
        if len(a) != len(b):
            return False
        for i in range(len(a)):
            if a[i] != b[i]:
                return False  # Early return!
        return True
    
    def safe_compare(a: bytes, b: bytes) -> bool:
        """SAFE: Constant-time comparison"""
        return hmac.compare_digest(a, b)
    
    # Demonstrate timing difference
    print("Timing attack demonstration:\n")
    
    test_cases = [
        b"wrong_token",
        b"super_secret",
        b"super_secret_api",
        b"super_secret_api_token",
        b"super_secret_api_token_12345",  # Correct!
    ]
    
    iterations = 10000
    
    print("Vulnerable comparison timings:")
    for test in test_cases:
        start = time.perf_counter()
        for _ in range(iterations):
            vulnerable_compare(test, correct_token)
        elapsed = (time.perf_counter() - start) * 1000
        match = "✓" if test == correct_token else "✗"
        print(f"  {match} '{test.decode()[:30]:30}' -> {elapsed:.3f}ms")
    
    print("\nConstant-time comparison timings:")
    for test in test_cases:
        start = time.perf_counter()
        for _ in range(iterations):
            safe_compare(test, correct_token)
        elapsed = (time.perf_counter() - start) * 1000
        match = "✓" if test == correct_token else "✗"
        print(f"  {match} '{test.decode()[:30]:30}' -> {elapsed:.3f}ms")
    
    print("\n⚠️  Notice: Vulnerable version takes longer as more bytes match!")
    print("   Attacker can guess token byte-by-byte by measuring response time.")
    print("   ALWAYS use hmac.compare_digest() or secrets.compare_digest()!")


# =============================================================================
# BONUS: BENCHMARK
# =============================================================================

def run_benchmarks():
    banner("BENCHMARK: Crypto Operations Performance")
    
    data_1kb = os.urandom(1024)
    data_1mb = os.urandom(1024 * 1024)
    iterations = 1000
    
    def bench(name, func, iterations=iterations):
        start = time.perf_counter()
        for _ in range(iterations):
            func()
        elapsed = (time.perf_counter() - start) * 1000 / iterations
        print(f"  {name:35} {elapsed:.4f} ms/op")
    
    print(f"Hash functions (1 KB data, {iterations} iterations):")
    bench("MD5", lambda: hashlib.md5(data_1kb).digest())
    bench("SHA-256", lambda: hashlib.sha256(data_1kb).digest())
    bench("SHA-512", lambda: hashlib.sha512(data_1kb).digest())
    bench("SHA3-256", lambda: hashlib.sha3_256(data_1kb).digest())
    bench("BLAKE2b", lambda: hashlib.blake2b(data_1kb).digest())
    bench("BLAKE3", lambda: blake3.blake3(data_1kb).digest())
    
    print(f"\nHash functions (1 MB data, 100 iterations):")
    bench("SHA-256 (1MB)", lambda: hashlib.sha256(data_1mb).digest(), 100)
    bench("BLAKE3 (1MB)", lambda: blake3.blake3(data_1mb).digest(), 100)
    
    print(f"\nSymmetric encryption (1 KB, {iterations} iterations):")
    key_aes = AESGCM.generate_key(256)
    key_chacha = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    aes = AESGCM(key_aes)
    chacha = ChaCha20Poly1305(key_chacha)
    
    bench("AES-256-GCM encrypt", lambda: aes.encrypt(nonce, data_1kb, None))
    bench("ChaCha20-Poly1305 encrypt", lambda: chacha.encrypt(nonce, data_1kb, None))
    
    print(f"\nAsymmetric operations (100 iterations):")
    rsa_key = rsa.generate_private_key(65537, 2048)
    rsa_pub = rsa_key.public_key()
    ed_key = ed25519.Ed25519PrivateKey.generate()
    
    bench("RSA-2048 sign", lambda: rsa_key.sign(
        data_1kb[:190],  # RSA has size limits
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    ), 100)
    
    bench("Ed25519 sign", lambda: ed_key.sign(data_1kb), 100)
    
    print("\n✅ BLAKE3 and ChaCha20 are typically fastest")
    print("   Ed25519 >> RSA for signing performance")


# =============================================================================
# MAIN
# =============================================================================

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║      CRYPTOGRAPHY & HASHING DEEP DIVE                             ║
    ║                                                                   ║
    ║   A comprehensive exploration of modern cryptographic primitives  ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    explore_hash_functions()
    explore_password_hashing()
    explore_symmetric_encryption()
    explore_asymmetric_encryption()
    explore_key_derivation()
    explore_macs_and_signatures()
    explore_merkle_trees()
    explore_shamirs_secret_sharing()
    explore_timing_attacks()
    run_benchmarks()
    
    print("\n" + "="*70)
    print("  deep dive, next query")
    print("="*70)


if __name__ == "__main__":
    main()
