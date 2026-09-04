# Phase 2 — Diffie–Hellman + AES-GCM (client↔server confidentiality)

Each client runs an **independent Diffie–Hellman** exchange with the server on
connect (implemented from scratch — see `my_mod_exp` in `crypto.c`), hashes the
raw DH secret with SHA-256 into an AES-256 key, and encrypts every frame with
**AES-256-GCM**. A MITM proxy is included as the attack tool.

DH uses the published **RFC 3526 Group 14 (2048-bit)** prime, generator 2. We
use OpenSSL's `bn.h` only as a big-integer type; we never include `dh.h` or
`ssl.h`.

## Files
- `server.cc` — DH per client; decrypts on the sender link, re-encrypts on the
  recipient link (so the server can still read chat — fixed in Phase 4).
- `client.cc` — DH handshake, AES-GCM, prints the shared-secret fingerprint.
- `mitm.cc` — man-in-the-middle proxy (the Phase 2 attack).
- `crypto.cc/.hh` — DH, AES-GCM, SHA-256, hex (shared building blocks).

## Build
```
make        # builds server, client, mitm
```

## Run — normal encrypted chat
```
./server 5000
./client <server_ip> 5000 alice
./client <server_ip> 5000 bob
```
Confirm the **shared-secret fingerprint** printed by each client matches the
one the server prints for that link.

## Run — MITM attack (Mallory VM)
Point the victim client at Mallory instead of the server:
```
# Server VM
./server 5000
# Mallory VM: listen on 5000, forward to the real server
./mitm 5000 <server_ip> 5000
# Victim client -> Mallory's IP
./client <mallory_ip> 5000 alice
# Other client -> straight to server (or also via Mallory)
./client <server_ip> 5000 bob
```
Mallory prints the captured plaintext (including the login and messages). The
victim's and server's fingerprints differ — the detectable evidence.

## Run — tamper detection
```
./mitm 5000 <server_ip> 5000 --tamper
```
Mallory flips one byte of each frame sent to the victim; the victim reports
`decryption/authentication FAILED` instead of showing corrupted text (GCM's
integrity tag).

## Report points (all required by sec 2)
- Why hash the DH secret: it is a group element — non-uniform and 256 bytes,
  not a key. SHA-256 gives a uniform, fixed-length 32-byte AES key and destroys
  algebraic structure.
- Fingerprints matched on both ends (screenshot).
- Wireshark: payload is now ciphertext, not readable text.
- MITM capture + the fingerprint mismatch that would expose it.
- Tamper test rejected by GCM.
