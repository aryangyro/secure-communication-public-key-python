# Work log

## 2026-11-20 — Secure communication with public key cryptography

**What was done**

- Built a secure communication system in one Python file (217 lines,
  standard library only): 2048-bit RSA key generation, RSA encryption and
  decryption, RSA digital signatures over a SHA-256 hash, an RSA-protected
  32-byte session key, and a Diffie-Hellman key exchange.
- Wrote 12 checks covering all five parts; all pass. The demo runs in
  under 3 seconds.
- Ran the demo and captured the real terminal output as 6 screenshots
  (one per part, plus a separate one for the tamper detection).
- Wrote the 1-page key-size report (2048-bit minimum, performance vs
  security, why symmetric encryption alone cannot start a conversation),
  the security challenge answers, and the short notes on tamper detection
  and hybrid encryption.
- Filled in the lab Word document: the first page is a cover page with the
  student's name and a short summary of what the lab is about, the
  professor's template instruction line was removed, the percentage was
  dropped from the title, and the screenshots and written answers were
  slotted in at their markers.

**Challenges**

- The `cryptography` library was not installed, so RSA had to be built
  from scratch with pure Python (Miller-Rabin prime generation and modular
  arithmetic). Generating a 1024-bit prime took about 1 second, so real
  2048-bit keys were still practical.
- The Word build script first failed on a page-break constant
  (`WD_BREAK.PAGE_BREAK` does not exist in this python-docx version;
  the correct name is `WD_BREAK.PAGE`).
- The signature screenshot first showed a truncated hex string because
  the whole line was cut to 60 characters; fixed by slicing the hex
  string itself to 32 characters.
