# Phase 4 — End-to-End Encryption (server can't read chat)

Adds a second Diffie–Hellman exchange **directly between the two clients**,
relayed through the server as opaque bytes. The resulting C1↔C2 key is known
only to the clients; chat is then double-encrypted (inner E2E layer + the
Phase 3 link layer).

**The server (`server.cc`) is byte-for-byte identical to Phase 3** — proof that
the relay never needs to understand end-to-end traffic.

## Wire tags (carried as the payload of a normal `@user` message)
| tag | meaning |
|-----|---------|
| `__E2E_INIT__<hexpub>` | initiator's DH public value |
| `__E2E_ACK__<hexpub>`  | responder's DH public value (completes the exchange) |
| `__E2E_MSG__<hexblob>` | an end-to-end AES-GCM encrypted message |

The server relays these opaquely; it never parses them.

## Build & run
```
make
./setup_ca.sh
./server 5000 pki/server.cert.pem pki/server.key.pem
./client <server_ip> 5000 alice pki/ca.cert.pem
./client <server_ip> 5000 bob   pki/ca.cert.pem
```
In alice's client:
```
@bob hello before e2e      # server logs this in plaintext
/e2e bob                   # establishes the end-to-end key
@bob secret after e2e      # server sees only __E2E_MSG__<hex>
```

## Report points (sec 4)
- Both clients print the **same** E2E fingerprint, derived without the server.
- Server relay log: plaintext before `/e2e`, opaque `__E2E_MSG__` after.
- Why the server cannot derive the key (it sees only the public DH values).
