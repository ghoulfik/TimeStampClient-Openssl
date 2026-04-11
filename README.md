# TSA Client (RFC 3161)

Jednoduchy RFC 3161 timestamp klient postaveny na OpenSSL. Komunikuje s TSA servermi na vytvaranie
casovych peciatok a ich lokalne overenie. Klient zhashuje vstupny subor (SHA-256), zostavuje TimeStampReq
a ulozuje prijaty token spolu s metadatami.

**Verzia**: `v1.60`

**Vychodzi server**: `DigiCert` (`timestamp.digicert.com:80/`)

## Build

Potrebujete OpenSSL dev kniznice (libssl, libcrypto) pre GCC/MinGW.

```
make
```

Vystup: `tsa_client_openssl.exe`

## Pouzitie

### Vytvorenie casovej peciatky

```
tsa_client_openssl.exe [--server NAME] <subor>
```

Priklady:
```
tsa_client_openssl.exe dokument.pdf
tsa_client_openssl.exe --server FreeTSA dokument.pdf
```

### Overenie casovej peciatky

```
tsa_client_openssl.exe -verify <subor> [token.tsr] [trusted_cert]
```

Mozete pouzit aj `--server` pred `-verify`, napriklad:
```
tsa_client_openssl.exe --server FreeTSA -verify dokument.pdf
```
Ak nezadate `[trusted_cert]` a zaroven pouzijete `--server`, klient automaticky vyberie
zodpovedajuci certifikat z adresara `Certificates/`.

Priklady:
```
tsa_client_openssl.exe -verify dokument.pdf
tsa_client_openssl.exe -verify dokument.pdf dokument.pdf.tsr
tsa_client_openssl.exe -verify dokument.pdf Certificates/FreeTSA.crt
tsa_client_openssl.exe --server DigiCert -verify dokument.pdf
```

Poznamka: Ak certifikat nie je poskytnuty, overenie najprv pouzije systemovy/OpenSSL trust store a pri potrebe sa prepne na fallback s podpisovym certifikatom ako trust anchor.
Ak certifikat je poskytnuty, pouzije sa ako trust anchor pre validaciu retaze.
Overenie vykonava validaciu certifikatovej retaze a kontroluje EKU id-kp-timeStamping.
Overenie vykonava aj kontrolu odvolania certifikatu signera cez OCSP a CRL (CRL Distribution Points).
Ak online odpoved nie je dostupna alebo certifikat neobsahuje OCSP/CRL URL, klient vypise upozornenie a pokracuje v overeni retaze.
Ak token nie je poskytnuty, automaticky sa pouzije `<subor>.tsr`.

## Podporovane TSA Servery

- **DigiCert** - `timestamp.digicert.com:80/` ✓ (test PASS)
- **FreeTSA** - `freetsa.org:80/tsr` ✓ (test PASS)
- **Sectigo** - `timestamp.sectigo.com:80/` ✓ (test PASS)
- **Certum** - `time.certum.pl:80/` ✓ (test PASS)
- **GlobalSign** - `timestamp.globalsign.com:80/tsa/r6advanced1` ✓ (test PASS)

## Certifikaty

V adresari `Certificates/` su dostupne TSA certifikaty:
- `DigiCert.cer`
- `FreeTSA.crt`
- `Sectigo.crt`
- `Certum.cer`
- `GlobalSign.crt`

## Vytvorene subory

Pri vytvarani peciatky sa vytvoria:
- `<subor>.tsr` - RFC 3161 casovy token (binarny)
- `<subor>.metadata.txt` - metadata (Gen cas, serial, policy, hash)

## Podporovane formaty

- **Hash (request path)**: SHA-256
- **Hash (verify path)**: SHA-256, SHA-384, SHA-512
- **Podpis signer certifikatu (verify path)**: RSA, ECDSA P-256, ECDSA P-384, ECDSA P-521
- **Validacia certifikatov (verify path)**: plna X.509 retaz (X509_verify_cert)
- **Revokacia certifikatov (verify path)**: OCSP (HTTP responder) + CRL (HTTP CRL Distribution Points)
- **Standard**: RFC 3161
- **Certifikaty**: X.509 (PEM/DER)
- **HTTP**: POST, chunked encoding (RFC 7230)
