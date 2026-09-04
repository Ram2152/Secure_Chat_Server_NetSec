#!/bin/bash

# Produces, inside ./pki/ :
#   ca.key.pem       CA private key                (keep secret, stays on CA/Server VM)
#   ca.cert.pem      self-signed CA root cert      (COPY to every client VM)
#   server.key.pem   chat server private key       (Server VM only)
#   server.csr.pem   certificate signing request
#   server.cert.pem  CA-signed server certificate  (Server VM)

set -e
CN=chatserver
DIR=pki
mkdir -p "$DIR"
cd "$DIR"

echo "[1/4] Creating Certificate Authority (CA root)..."
openssl genrsa -out ca.key.pem 2048
openssl req -x509 -new -nodes -key ca.key.pem -sha256 -days 3650 \
    -subj "/C=IN/ST=TN/O=CS6008 Demo CA/CN=CS6008-Root-CA" \
    -out ca.cert.pem

echo "[2/4] Creating server key and CSR (CN=${CN})..."
openssl genrsa -out server.key.pem 2048
openssl req -new -key server.key.pem \
    -subj "/C=IN/ST=TN/O=CS6008 Chat/CN=${CN}" \
    -out server.csr.pem

echo "[3/4] CA signs the CSR -> server certificate..."
openssl x509 -req -in server.csr.pem \
    -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial \
    -days 365 -sha256 -out server.cert.pem

echo "[4/4] Creating an attacker self-signed cert (same CN, NOT CA-signed)..."
openssl genrsa -out attacker_fake.key.pem 2048
openssl req -x509 -new -nodes -key attacker_fake.key.pem -sha256 -days 365 \
    -subj "/C=IN/ST=TN/O=Evil Corp/CN=${CN}" \
    -out attacker_fake.cert.pem

echo
echo "Sanity check (should say OK):"
openssl verify -CAfile ca.cert.pem server.cert.pem
echo
echo "Done. Files are in ./pki/"
echo "  Server VM needs : server.cert.pem, server.key.pem"
echo "  Client VMs need : ca.cert.pem"
