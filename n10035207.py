# Aryan Panwar — n10035207
"""Lab 6: Secure communication between two hospitals using public key
cryptography. RSA for encryption and signatures, Diffie-Hellman for a
shared secret. Standard library only."""

import hashlib
import secrets

# ---------- maths helpers ----------

def is_probable_prime(n, rounds=8):
    """Miller-Rabin test: True if n is probably prime."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """Random prime of the given bit length."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def mod_inverse(a, m):
    """Inverse of a modulo m (a and m must be coprime)."""
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


# ---------- RSA ----------

def gen_rsa_keypair(bits=2048):
    """Return (public, private) where public = (e, n), private = (d, n)."""
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def rsa_encrypt(message, public):
    """Encrypt bytes with a public key; returns an int (ciphertext)."""
    e, n = public
    m = int.from_bytes(message, "big")
    if m >= n:
        raise ValueError("message too long for this key")
    return pow(m, e, n)


def rsa_decrypt(ciphertext, private):
    """Decrypt an int ciphertext with a private key; returns bytes."""
    d, n = private
    m = pow(ciphertext, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def rsa_sign(message, private):
    """Sign a message: hash it with SHA-256, then sign the hash."""
    d, n = private
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return pow(digest, d, n)


def rsa_verify(message, signature, public):
    """True if the signature matches the message under the public key."""
    e, n = public
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return pow(signature, e, n) == digest


def fingerprint(public):
    """Short SHA-256 fingerprint of a public key, for sharing safely."""
    e, n = public
    return hashlib.sha256(f"{e}:{n}".encode()).hexdigest()[:16]


def save_key(path, key):
    with open(path, "w") as f:
        f.write(f"{key[0]}\n{key[1]}\n")


def load_key(path):
    with open(path) as f:
        a, b = f.read().split()
    return (int(a), int(b))


# ---------- Task 2: hospital identity setup ----------

def task2_identity():
    print("=== Task 2: Hospital Identity Setup ===")
    hospital_a_pub, hospital_a_priv = gen_rsa_keypair()
    hospital_b_pub, hospital_b_priv = gen_rsa_keypair()
    # Private keys stay in files only the owner can read (in a real
    # system they would also be encrypted with a password).
    save_key("hospital_a_private.key", hospital_a_priv)
    save_key("hospital_b_private.key", hospital_b_priv)
    # Public keys are shared with the other hospital.
    save_key("hospital_a_public.key", hospital_a_pub)
    save_key("hospital_b_public.key", hospital_b_pub)
    print("Hospital A key pair generated (2048-bit RSA)")
    print("Hospital B key pair generated (2048-bit RSA)")
    print(f"Hospital A public key fingerprint: {fingerprint(hospital_a_pub)}")
    print(f"Hospital B public key fingerprint: {fingerprint(hospital_b_pub)}")
    print("Private keys saved: hospital_a_private.key, hospital_b_private.key")
    print("Public keys shared: hospital_a_public.key, hospital_b_public.key")
    return hospital_a_pub, hospital_a_priv, hospital_b_pub, hospital_b_priv


# ---------- Task 3: confidential patient data transfer ----------

def task3_message(hospital_b_pub, hospital_b_priv):
    print("=== Task 3: Confidential Patient Data Transfer ===")
    message = b"Patient ID 98321 requires immediate cardiac intervention."
    cipher = rsa_encrypt(message, hospital_b_pub)
    print(f"Hospital A sends (encrypted with B's public key):")
    print(f"  ciphertext: {cipher:x}"[:80] + "...")
    plain = rsa_decrypt(cipher, hospital_b_priv)
    print(f"Hospital B decrypts with its private key: {plain.decode()}")
    print(f"Decryption correct: {plain == message}")


# ---------- Task 4: digital signatures ----------

def task4_signature(hospital_a_pub, hospital_a_priv):
    print("=== Task 4: Medical Authentication System ===")
    result = b"Glucose level: 6.5 mmol/L"
    signature = rsa_sign(result, hospital_a_priv)
    print(f"Doctor signs the lab result: {result.decode()}")
    sig_hex = f"{signature:x}"[:32]
    print(f"Signature (first 32 hex chars): {sig_hex}")
    print(f"Hospital B verifies with A's public key: "
          f"{'VALID' if rsa_verify(result, signature, hospital_a_pub) else 'INVALID'}")
    tampered = b"Glucose level: 16.5 mmol/L"
    print(f"Attacker changes the result to: {tampered.decode()}")
    print(f"Signature check on tampered result: "
          f"{'VALID' if rsa_verify(tampered, signature, hospital_a_pub) else 'INVALID - TAMPERING DETECTED'}")


# ---------- Task 5: session key exchange ----------

def task5_session(hospital_b_pub, hospital_b_priv):
    print("=== Task 5: Secure Session Key Exchange ===")
    session_key = secrets.token_bytes(32)  # a 256-bit AES session key
    cipher = rsa_encrypt(session_key, hospital_b_pub)
    print("Hospital A creates a random 32-byte session key")
    print(f"Session key encrypted with B's public key: {cipher:x}"[:80] + "...")
    recovered = rsa_decrypt(cipher, hospital_b_priv)
    print(f"Hospital B decrypts it with its private key: {recovered == session_key}")
    print("Both hospitals now share the session key,")
    print("and the large dataset can be encrypted with fast AES (hybrid encryption).")


# ---------- Task 6: Diffie-Hellman ----------

def task6_diffie_hellman():
    print("=== Task 6: Diffie-Hellman Key Exchange ===")
    p = gen_prime(256)  # public prime, known to everyone
    g = 2               # public generator
    a = secrets.randbelow(p - 2) + 2  # Hospital A private value (kept secret)
    b = secrets.randbelow(p - 2) + 2  # Hospital B private value (kept secret)
    a_pub = pow(g, a, p)  # sent over the insecure channel
    b_pub = pow(g, b, p)  # sent over the insecure channel
    print(f"Public prime p: {p}")
    print(f"Hospital A sends public value: {a_pub}")
    print(f"Hospital B sends public value: {b_pub}")
    secret_a = pow(b_pub, a, p)  # A computes the shared secret
    secret_b = pow(a_pub, b, p)  # B computes the shared secret
    print(f"Hospital A shared secret: {secret_a}")
    print(f"Hospital B shared secret: {secret_b}")
    print(f"Both sides agree: {secret_a == secret_b}")
    print("An eavesdropper sees only p, g and the public values,")
    print("and cannot work out the secret from them.")


def main():
    a_pub, a_priv, b_pub, b_priv = task2_identity()
    print()
    task3_message(b_pub, b_priv)
    print()
    task4_signature(a_pub, a_priv)
    print()
    task5_session(b_pub, b_priv)
    print()
    task6_diffie_hellman()


if __name__ == "__main__":
    main()
