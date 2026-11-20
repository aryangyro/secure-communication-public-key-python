# Secure Communication with Public Key Cryptography

A small secure communication system between two hospitals, built in Python
with the standard library only: RSA key pairs, RSA encryption, digital
signatures, an RSA-protected session key, and a Diffie-Hellman exchange.

## What it does

- **Key setup** — each hospital generates its own 2048-bit RSA key pair,
  saves its private key to a file, and shares its public key with the other
  hospital. A short SHA-256 fingerprint lets the other side check the key
  it received.
- **Confidential messages** — Hospital A encrypts a patient message with
  Hospital B's public key, so only B can read it with its private key.
- **Digital signatures** — a doctor signs a lab result with the private key
  (the SHA-256 hash of the message is what gets signed). The other hospital
  verifies it with the public key. Changing the result after signing makes
  the check fail, so tampering is caught.
- **Session keys** — a random 32-byte session key is encrypted with RSA and
  sent over, so both sides share a key without it ever travelling in the
  open. The bulk data would then use fast AES with that key (hybrid
  encryption).
- **Diffie-Hellman** — both hospitals pick a private value, exchange public
  values over an insecure channel, and each computes the same shared secret
  on its own. An eavesdropper sees only the public values and cannot work
  out the secret.

Run it with:

```text
python3 n10035207.py
```

It runs all five parts in order and prints the results to the terminal.

## Files

- `n10035207.py` — the system (217 lines, standard library only: `hashlib`,
  `secrets`). RSA is implemented from scratch with Miller-Rabin prime
  generation, so there are no outside dependencies to install.
- `test_lab6.py` — 12 quick checks for the five parts.
- `WORKLOG.md` — what was done and what the challenges were.

## What it shows

Public key cryptography solves the problem symmetric encryption cannot:
two parties that have never met can agree on keys and prove who sent what
over a network anyone can listen on. RSA handles the small, sensitive jobs
(keys and signatures) while a fast symmetric cipher handles the bulk data,
which is why real systems use both together.
