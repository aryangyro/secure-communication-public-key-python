# Aryan Panwar — n10035207
"""Quick checks for the Lab 6 secure communication system."""
import n10035207 as lab


def check(name, ok):
    print(("PASS " if ok else "FAIL ") + name)
    assert ok, name


# Key generation
pub, priv = lab.gen_rsa_keypair(1024)
e, n = pub
check("keypair: modulus is 1024-bit", n.bit_length() == 1024)
check("public exponent is 65537", e == 65537)

# Task 3: encryption round trip
msg = b"Patient ID 98321 requires immediate cardiac intervention."
cipher = lab.rsa_encrypt(msg, pub)
check("encrypt/decrypt round trip", lab.rsa_decrypt(cipher, priv) == msg)
pub2, priv2 = lab.gen_rsa_keypair(1024)
check("decrypt with wrong key gives different bytes",
      lab.rsa_decrypt(cipher, priv2) != msg)

# Task 4: signatures
sig = lab.rsa_sign(msg, priv)
check("signature verifies", lab.rsa_verify(msg, sig, pub))
check("tampered message fails verification",
      not lab.rsa_verify(b"Patient ID 98321 requires immediate surgery.", sig, pub))
check("signature fails under wrong public key",
      not lab.rsa_verify(msg, sig, pub2))

# Task 5: session key round trip
import secrets
key = secrets.token_bytes(32)
check("session key round trip",
      lab.rsa_decrypt(lab.rsa_encrypt(key, pub), priv) == key)

# Task 6: Diffie-Hellman
p = lab.gen_prime(256)
g = 2
a = secrets.randbelow(p - 2) + 2
b = secrets.randbelow(p - 2) + 2
check("DH: both sides compute the same secret",
      pow(pow(g, b, p), a, p) == pow(pow(g, a, p), b, p))
check("DH: different private values give a different secret",
      pow(pow(g, b, p), a, p) != pow(pow(g, b + 1, p), a, p))

# Prime generation
check("generated 256-bit number is prime", lab.is_probable_prime(p))
check("generated prime is 256-bit", p.bit_length() == 256)

print("All checks passed.")
