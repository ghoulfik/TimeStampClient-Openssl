# TSA Client (RFC 3161)

Jednoduchy RFC 3161 timestamp klient postaveny na OpenSSL. Komunikuje s TSA servermi na vytvaranie
casovych peciaток a ich lokalne overenie. Klient zhashuje vstupny subor (SHA-256), zostavuje TimeStampReq
a ulozuje prijaty token spolu s metadatami.

**Verzia**: `v1.50`

**Vychodzi server**: `DigiCert` (`timestamp.digicert.com:80/`)

## Build

Potrebujete OpenSSL dev kniznice (libssl, libcrypto) pre GCC/MinGW.

```
make
```

Vystup: `tsa_client_openssl.exe` na Windows, `tsa_client_openssl` na Linux/macOS.

Na Linuxe a macOS Makefile pouziva `pkg-config` pre OpenSSL, ak je dostupny; inak skusa klasicke `-lssl -lcrypto`.

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

Priklady:
```
tsa_client_openssl.exe -verify dokument.pdf
tsa_client_openssl.exe -verify dokument.pdf dokument.pdf.tsr
tsa_client_openssl.exe -verify dokument.pdf Certificates/FreeTSA.crt
```

Poznamka: Ak certifikat nie je poskytnuty, overuje sa iba podpis.
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

- **Hash**: SHA-256
- **Standard**: RFC 3161
- **Certifikaty**: X.509 (PEM/DER)
- **HTTP**: POST, chunked encoding (RFC 7230)
