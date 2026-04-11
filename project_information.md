# Project Information

## General

- Version number/name: v1.60
- Release date: 2026-04-09
- Brief description of what changed: OpenSSL TSA client with improved verify-path support, including SHA-384/SHA-512 message imprint verification, ECDSA curve support, chain validation with signer-anchor fallback, and TSA EKU enforcement.

## Features & Functionality

- Supported timestamp servers (TSA endpoints):
  - DigiCert - `timestamp.digicert.com:80/`
  - FreeTSA - `freetsa.org:80/tsr`
  - Sectigo - `timestamp.sectigo.com:80/`
  - Certum - `time.certum.pl:80/`
  - GlobalSign - `timestamp.globalsign.com:80/tsa/r6advanced1`
- Token generation:
  - Builds RFC 3161 TimeStampReq and sends it via HTTP POST using OpenSSL BIO.
  - Uses SHA-256 for request generation.
  - Saves the returned timestamp token as `<file>.tsr` and writes metadata to `<file>.metadata.txt`.
- Token verification:
  - Supports generated token verification from `<file>.tsr`.
  - Supports user-provided token files.
  - Supports optional user-provided certificate trust material.
  - Verifies message imprint algorithms SHA-256, SHA-384, and SHA-512 in the verify path.
  - Supports RSA and ECDSA signer verification, including ECDSA P-256, P-384, and P-521.
- File format support:
  - Input files are treated as binary streams.
  - Certificate inputs may be PEM or DER (`.crt`, `.cer`, `.pem`, `.der`).
  - Timestamp tokens are handled as RFC 3161 TS_RESP DER data.
  - Limitation: request generation still uses SHA-256 only.
- New or removed features:
  - Added certificate chain validation in verify mode.
  - Added a signer-anchor fallback when no certificate is supplied and the default trust store cannot build the chain.
  - Added TSA EKU enforcement (`id-kp-timeStamping`).
  - No removed user-facing features.

## Performance & Speed

- Average time to create a timestamp: not formally benchmarked in the repository; depends mainly on network latency and TSA server response time.
- Average time to verify a timestamp: not formally benchmarked; local verification is fast, while chain validation depends on trust store lookup and certificate chain depth.
- Known bottlenecks or improvements:
  - Network round-trip to TSA is the dominant cost during timestamp creation.
  - Verification now performs chain validation with a fallback trust-anchor path, which is slightly more expensive than the earlier heuristic certificate matching but significantly more correct and secure.
  - File hashing is chunked, so large input files do not need to be loaded fully into memory.

## Security & Certificates

- Certificate types/standards supported:
  - X.509 certificates
  - RFC 3161 timestamp tokens
  - SHA-256, SHA-384, SHA-512 in the verify path
  - RSA and ECDSA signer certificates
- Certificate handling/validation:
  - Uses OpenSSL PKCS7, TS, EVP, and X509 APIs.
  - Validates the signer through X.509 chain building.
  - Uses the system/OpenSSL trust store when no certificate is provided, then falls back to the signer certificate as an anchor if the default store cannot build the chain.
  - Uses a supplied certificate as trust anchor material when provided.
  - Enforces TSA extended key usage (`id-kp-timeStamping`).
- Security fixes or vulnerabilities addressed:
  - Replaced heuristic signer matching with chain validation and signer-anchor fallback.
  - Removed dependency on exact certificate-name matching for successful verify.
  - Added support for stronger digest algorithms in the verify path.
- Hash algorithm used:
  - Request generation: SHA-256
  - Verify path: SHA-256, SHA-384, SHA-512
