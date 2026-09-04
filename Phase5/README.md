# Phase 5 — Forward Secrecy (periodic key rotation)

Extends Phase 4: the end-to-end key is renegotiated on a fixed timer
(**default 60s**) with a fresh ephemeral Diffie–Hellman each time, so every
epoch's key is independent. Compromising one key does not expose past or future
epochs. The server (`server.cc`) is still identical to Phase 3.

## Design decisions
- **Epochs.** Every key has an epoch number. Messages are stamped with the
  epoch that encrypted them: `__E2E_MSG__<epoch>:<hex>`. Each side keeps the
  **current** and the **immediately previous** key, so a message sent just
  before a rotation still decrypts just after it — chat is never disrupted. The
  key before that is overwritten (discarded), so an old key is never used to
  encrypt new traffic once the new one is confirmed.
- **Collision avoidance by role.** Both clients run a rekey timer, but only the
  client with the lexicographically **smaller username** actually initiates a
  rotation; the other only responds. Two competing exchanges therefore cannot
  happen, so the two sides never diverge onto different keys. (This *prevents*
  the simultaneous-trigger case rather than resolving it after the fact.)

## Extra commands
| command | effect |
|---------|--------|
| `/rekey`  | force an immediate rotation (initiator only) |
| `/keyage` | print current epoch, key fingerprint, key age, and role |

## Build & run
```
make
./setup_ca.sh
./server 5000 pki/server.cert.pem pki/server.key.pem
./client <server_ip> 5000 alice pki/ca.cert.pem
./client <server_ip> 5000 bob   pki/ca.cert.pem
# in alice: /e2e bob, then chat
```

### Demonstrating rotation quickly
The 60s default is spec-compliant but slow to demo. For screenshots you may
shorten the interval with an environment variable (a testing aid only):
```
E2E_REKEY_SECONDS=5 ./client <server_ip> 5000 alice pki/ca.cert.pem
E2E_REKEY_SECONDS=5 ./client <server_ip> 5000 bob   pki/ca.cert.pem
```
…or just press `/rekey` in alice's client. Use `/keyage` on both to confirm they
agree on the current epoch and fingerprint.

## Report points (sec 5)
- Logs from both clients showing ≥2 rotations, each with a **new** fingerprint,
  **matching** across the two sides per epoch.
- A message sent right around a rotation still delivered and readable.
- Your collision-avoidance approach and why it is correct.
