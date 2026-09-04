#!/bin/bash
set -e

CN=chatserver
DIR=pki

mkdir -p "$DIR"
cd "$DIR"

# Certificate validity: 1 minute
NOT_AFTER=$(date -u -d '+5 minute' '+%Y%m%d%H%M%SZ')

echo "[1/4] Creating Certificate Authority (CA root)..."
openssl genrsa -out ca.key.pem 2048

openssl req -x509 -new -nodes -key ca.key.pem -sha256 \
    -not_after "$NOT_AFTER" \
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
    -sha256 \
    -not_after "$NOT_AFTER" \
    -out server.cert.pem

echo "[4/4] Creating attacker self-signed cert (same CN, NOT CA-signed)..."
openssl genrsa -out attacker_fake.key.pem 2048

openssl req -x509 -new -nodes -key attacker_fake.key.pem -sha256 \
    -not_after "$NOT_AFTER" \
    -subj "/C=IN/ST=TN/O=Evil Corp/CN=${CN}" \
    -out attacker_fake.cert.pem
