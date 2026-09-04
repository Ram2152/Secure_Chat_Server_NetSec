# Phase 3 — PKI Server Authentication (defeats the MITM)

Adds a CA-signed server certificate and a **proof-of-possession** step so the
client can be sure it is talking to the real server, not a MITM. The Phase 2
attack now fails.

## Handshake
1. `S → C` server certificate (PEM)
2. client validates it against the CA: **(a)** signature by the CA, **(b)**
   validity period, **(c)** CN = `chatserver`. Aborts on any failure.
3. `C → S` 32-byte random challenge nonce
4. `S → C` server DH public value
5. `S → C` signature over `(nonce ‖ server_DH_pub)` using the server's
   **private** key
6. client verifies that signature with the certificate's public key
7. `C → S` client DH public value → both derive the AES key (as in Phase 2)

Signing `(nonce ‖ server_DH_pub)` proves the server holds the private key **and**
binds the DH key to the certified identity, so a MITM cannot substitute its own
DH key.

## Build & PKI setup
```
make
./setup_ca.sh      # creates ./pki/ : ca.cert.pem, server.cert.pem, server.key.pem, attacker_fake.*
```
Distribute `pki/ca.cert.pem` to client VMs; keep `server.key.pem` on the server.

## Run — legitimate flow
```
./server 5000 pki/server.cert.pem pki/server.key.pem
./client <server_ip> 5000 alice pki/ca.cert.pem
./client <server_ip> 5000 bob   pki/ca.cert.pem
```
Client prints `certificate OK` and `proof-of-possession OK`, then chat works.

## Run — attack 1: forged (self-signed) certificate → rejected at validation
```
./mitm 5000 fake pki/attacker_fake.cert.pem pki/attacker_fake.key.pem
./client <mallory_ip> 5000 alice pki/ca.cert.pem
```
Client aborts: *certificate signature not from trusted CA*.

## Run — attack 2: stolen real certificate, no private key → rejected at PoP
```
./mitm 5000 stolen pki/server.cert.pem pki/attacker_fake.key.pem
./client <mallory_ip> 5000 alice pki/ca.cert.pem
```
Certificate validates (it's real) but the client aborts:
*PROOF-OF-POSSESSION FAILED* — the attacker can't sign with the server's key.

## Report points (sec 3)
- The three validation checks and why each matters.
- How PoP binds identity to the DH key and defeats the Phase 2 MITM.
- Screenshots of both attacks being rejected.
