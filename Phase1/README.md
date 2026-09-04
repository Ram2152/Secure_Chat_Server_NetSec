# Phase 1 — Baseline Chat (no security)

A multi-client TCP relay chat. The server relays messages by username and
**logs all content in plaintext**, demonstrating that at this stage anyone on
the wire (and the server itself) can read everything.

## Files
- `server.cc` — thread-per-client relay; prints every relayed message.
- `client.cc` — the required command interface.
- `common.cc/.hh` — length-prefixed TCP framing (shared, unchanged, in every phase).

## Build
```
make
```

## Run (loopback for development; use VM IPs for the demo)
```
# terminal 1 (Server VM)
./server 5000

# terminal 2 (Client VM C1)
./client <server_ip> 5000 alice

# terminal 3 (Client VM C2)
./client <server_ip> 5000 bob
```

## Command interface
| input | effect |
|-------|--------|
| `@bob hello`   | send "hello" to bob and make bob the current partner |
| `/chat bob`    | switch current partner to bob (no message sent) |
| `/who`         | list online users |
| `/quit`        | disconnect |
| any other text | sent to the current partner |

## What to capture for the report
- Server console showing it printing the full plaintext of every message.
- Wireshark on the Client↔Server link: the chat text is visible in the TCP
  payload (this is the vulnerability Phase 2 fixes).
