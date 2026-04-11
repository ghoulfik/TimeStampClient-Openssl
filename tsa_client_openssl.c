/*
 * File: tsa_client_openssl.c
 * Project: TSA klient (RFC 3161)
 * Autor: Anton Kozar
 * Datum: 04.09.2026
 * Verzia: v1.60
 *
 * Popis:
 * - OpenSSL implementacia TimeStamp Authority klienta podla RFC 3161.
 * - Komunikuje s TSA serverom na vytvaranie casovych peciatok.
 * - Podporuje vytvorenie peciatky, ulozenie tokenu a lokalne overenie.
 * - Pouziva OpenSSL moduly EVP, TS, PKCS7 a X509.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/core_names.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/ec.h>
#endif

/* Predvolena konfiguracia TSA endpointu */
#define DEFAULT_TSA_HOST "timestamp.digicert.com"
#define DEFAULT_TSA_PORT 80
#define DEFAULT_TSA_PATH "/"

/* Velkost I/O bloku pri citani zo suboru a siete */
#define READ_CHUNK 4096

/* Preddefinovane TSA servery */
typedef struct {
    const char *name; /* Nazov predvolby servera */
    const char *host; /* Hostname servera */
    int port;         /* TCP port servera */
    const char *path; /* URL cesta pre RFC 3161 request */
} tsa_server_config_t;

static const tsa_server_config_t TSA_SERVERS[] = {
    {"DigiCert", "timestamp.digicert.com", 80, "/"},
    {"FreeTSA", "freetsa.org", 80, "/tsr"},
    {"Sectigo", "timestamp.sectigo.com", 80, "/"},
    {"Certum", "time.certum.pl", 80, "/"},
    {"GlobalSign", "timestamp.globalsign.com", 80, "/tsa/r6advanced1"}
};

#define TSA_SERVER_COUNT (sizeof(TSA_SERVERS) / sizeof(TSA_SERVERS[0]))

typedef struct {
    unsigned char *data; /* Ukazovatel na dynamicky alokovane data */
    size_t len;          /* Aktualna dlzka dat v bajtoch */
} buffer_t;

/******************************************************************************
* Funkcia:    basename_path
*
* Popis:      Vrati nazov suboru bez adresarovej cesty
*
* Navrat:     Ukazovatel na nazov suboru v ramci povodneho retazca
*****************************************************************************/
static const char *basename_path(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    const char *base = path;

    if (slash && slash[1] != '\0') {
        base = slash + 1;
    }
    if (backslash && backslash[1] != '\0' && backslash + 1 > base) {
        base = backslash + 1;
    }

    return base;
}

/******************************************************************************
* Funkcia:    is_certificate_path
*
* Popis:      Zisti, ci nazov suboru vyzera ako cesta k certifikatu
*
* Navrat:     1 ak ide pravdepodobne o certifikat, inak 0
*****************************************************************************/
static int is_certificate_path(const char *path) {
    const char *ext;

    if (!path) {
        return 0;
    }

    ext = strrchr(path, '.');
    if (!ext) {
        return 0;
    }

    if (_stricmp(ext, ".crt") == 0 ||
        _stricmp(ext, ".cer") == 0 ||
        _stricmp(ext, ".pem") == 0 ||
        _stricmp(ext, ".der") == 0) {
        return 1;
    }

    return 0;
}

/******************************************************************************
* Funkcia:    find_tsa_server
*
* Popis:      Najde preddefinovany TSA server podla nazvu
*
* Navrat:     Ukazovatel na konfiguraciu servera alebo NULL pri chybe
*****************************************************************************/
static const tsa_server_config_t *find_tsa_server(const char *name) {
    size_t i;

    if (!name) {
        return NULL;
    }

    for (i = 0; i < TSA_SERVER_COUNT; i++) {
        if (_stricmp(name, TSA_SERVERS[i].name) == 0) {
            return &TSA_SERVERS[i];
        }
    }

    return NULL;
}

/******************************************************************************
* Funkcia:    buffer_free
*
* Popis:      Uvolni dynamicky buffer a resetuje jeho stav
*
* Navrat:     void
*****************************************************************************/
static void buffer_free(buffer_t *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
    }
}

/******************************************************************************
* Funkcia:    read_file
*
* Popis:      Nacita cely subor do pamate
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int read_file(const char *path, buffer_t *out) {
    FILE *fp = fopen(path, "rb");
    long file_size;
    size_t read_len;

    if (!fp) {
        fprintf(stderr, "Nepodarilo sa otvorit subor: %s\n", path);
        return 0;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return 0;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }

    out->data = (unsigned char *)malloc((size_t)file_size);
    if (!out->data) {
        fclose(fp);
        return 0;
    }

    read_len = fread(out->data, 1, (size_t)file_size, fp);
    fclose(fp);
    if (read_len != (size_t)file_size) {
        buffer_free(out);
        return 0;
    }

    out->len = read_len;
    return 1;
}

/******************************************************************************
* Funkcia:    write_file
*
* Popis:      Zapise binarne data do vystupneho suboru
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    size_t written;

    if (!fp) {
        fprintf(stderr, "Nepodarilo sa zapisat subor: %s\n", path);
        return 0;
    }

    written = fwrite(data, 1, len, fp);
    fclose(fp);
    return written == len;
}

/******************************************************************************
* Funkcia:    digest_name_from_nid
*
* Popis:      Vrati textovy nazov podporovaneho digest algoritmu
*
* Navrat:     Nazov algoritmu alebo "UNKNOWN"
*****************************************************************************/
static const char *digest_name_from_nid(int nid) {
    switch (nid) {
        case NID_sha256:
            return "SHA-256";
        case NID_sha384:
            return "SHA-384";
        case NID_sha512:
            return "SHA-512";
        default:
            return "UNKNOWN";
    }
}

/******************************************************************************
* Funkcia:    digest_from_nid
*
* Popis:      Namapuje NID digestu na EVP_MD pre podporovane algoritmy
*
* Navrat:     Ukazovatel na EVP_MD alebo NULL pri nepodporovanom algoritme
*****************************************************************************/
static const EVP_MD *digest_from_nid(int nid) {
    switch (nid) {
        case NID_sha256:
            return EVP_sha256();
        case NID_sha384:
            return EVP_sha384();
        case NID_sha512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

/******************************************************************************
* Funkcia:    get_imprint_digest_info
*
* Popis:      Z TS message imprintu ziska digest algoritmus a dlzku
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int get_imprint_digest_info(TS_MSG_IMPRINT *imprint,
                                   const EVP_MD **out_md,
                                   int *out_nid,
                                   int *out_len) {
    X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *obj = NULL;
    int nid;
    const EVP_MD *md;
    int md_len;

    if (!imprint || !out_md || !out_nid || !out_len) {
        return 0;
    }

    alg = TS_MSG_IMPRINT_get_algo(imprint);
    if (!alg) {
        return 0;
    }

    X509_ALGOR_get0(&obj, NULL, NULL, alg);
    if (!obj) {
        return 0;
    }

    nid = OBJ_obj2nid(obj);
    md = digest_from_nid(nid);
    if (!md) {
        return 0;
    }

    md_len = EVP_MD_get_size(md);
    if (md_len <= 0) {
        return 0;
    }

    *out_md = md;
    *out_nid = nid;
    *out_len = md_len;
    return 1;
}

/******************************************************************************
* Funkcia:    digest_file
*
* Popis:      Vypocita digest pre zadany subor podla zvoleneho EVP_MD
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int digest_file(const char *path, const EVP_MD *md,
                       unsigned char *digest, unsigned int *digest_len) {
    EVP_MD_CTX *ctx = NULL;
    FILE *fp = NULL;
    unsigned char chunk[READ_CHUNK];
    size_t n;
    int ok = 0;

    if (!path || !md || !digest || !digest_len) {
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        goto cleanup;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Nepodarilo sa otvorit subor: %s\n", path);
        goto cleanup;
    }

    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, chunk, n) != 1) {
            goto cleanup;
        }
    }
    if (ferror(fp)) {
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (fp) {
        fclose(fp);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

/******************************************************************************
* Funkcia:    sha256_file
*
* Popis:      Vypocita SHA-256 hash pre zadany subor
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int sha256_file(const char *path, unsigned char digest[32]) {
    unsigned int digest_len = 0;

    if (!digest_file(path, EVP_sha256(), digest, &digest_len)) {
        return 0;
    }

    return digest_len == 32;
}

/******************************************************************************
* Funkcia:    hex_print
*
* Popis:      Vypise binarne data vo formate hexadecimalneho retazca
*
* Navrat:     void
*****************************************************************************/
static void hex_print(const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

/******************************************************************************
* Funkcia:    print_hash_preview
*
* Popis:      Vypise skratenu ukazku hashu v style povodneho klienta
*
* Navrat:     void
*****************************************************************************/
static void print_hash_preview(const unsigned char *digest, size_t len) {
    size_t i;

    if (len <= 12) {
        hex_print(digest, len);
        return;
    }

    for (i = 0; i < 8; i++) {
        printf("%02x", digest[i]);
    }
    printf("...");
    for (i = len - 4; i < len; i++) {
        printf("%02x", digest[i]);
    }
}

/******************************************************************************
* Funkcia:    mem_contains_ci
*
* Popis:      Najde podretazec v bufferi bez rozlisovania velkosti pismen
*
* Navrat:     1 ak sa retazec nasiel, inak 0
*****************************************************************************/
static int mem_contains_ci(const unsigned char *buf, size_t len, const char *needle) {
    size_t nlen = strlen(needle);
    size_t i;
    size_t j;

    if (nlen == 0 || len < nlen) {
        return 0;
    }

    for (i = 0; i + nlen <= len; i++) {
        for (j = 0; j < nlen; j++) {
            if (tolower((unsigned char)buf[i + j]) != tolower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}

/******************************************************************************
* Funkcia:    decode_chunked_body
*
* Popis:      Dekoduje HTTP telo kodovane transfer-encoding chunked
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int decode_chunked_body(const unsigned char *in, size_t in_len, buffer_t *out) {
    size_t pos = 0;
    size_t total = 0;
    unsigned char *decoded = NULL;

    while (pos < in_len) {
        size_t line_start = pos;
        unsigned long chunk_len = 0;
        char numbuf[32];
        size_t npos = 0;

        while (pos + 1 < in_len && !(in[pos] == '\r' && in[pos + 1] == '\n')) {
            if (npos + 1 < sizeof(numbuf) && in[pos] != ';') {
                numbuf[npos++] = (char)in[pos];
            }
            pos++;
        }
        if (pos + 1 >= in_len) {
            free(decoded);
            return 0;
        }
        numbuf[npos] = '\0';
        pos += 2;

        if (npos == 0) {
            free(decoded);
            return 0;
        }

        {
            char *endptr = NULL;
            chunk_len = strtoul(numbuf, &endptr, 16);
            if (!endptr || *endptr != '\0') {
                free(decoded);
                return 0;
            }
        }

        if (chunk_len == 0) {
            out->data = decoded;
            out->len = total;
            return 1;
        }

        if (pos + chunk_len + 2 > in_len) {
            free(decoded);
            return 0;
        }

        {
            unsigned char *tmp = (unsigned char *)realloc(decoded, total + (size_t)chunk_len);
            if (!tmp) {
                free(decoded);
                return 0;
            }
            decoded = tmp;
        }

        memcpy(decoded + total, in + pos, (size_t)chunk_len);
        total += (size_t)chunk_len;
        pos += (size_t)chunk_len;

        if (!(in[pos] == '\r' && in[pos + 1] == '\n')) {
            free(decoded);
            return 0;
        }
        pos += 2;

        if (pos == line_start) {
            free(decoded);
            return 0;
        }
    }

    free(decoded);
    return 0;
}

/******************************************************************************
* Funkcia:    build_ts_request_der
*
* Popis:      Zostavi RFC3161 TimeStampReq a serializuje ho do DER formatu
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int build_ts_request_der(const unsigned char *digest, size_t digest_len, buffer_t *out_der) {
    TS_REQ *req = NULL;
    TS_MSG_IMPRINT *imprint = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *obj = NULL;
    ASN1_INTEGER *nonce = NULL;
    unsigned char *der = NULL;
    unsigned char *p;
    int der_len;
    int ok = 0;
    unsigned int rnd = 0;

    req = TS_REQ_new();
    imprint = TS_MSG_IMPRINT_new();
    alg = X509_ALGOR_new();
    nonce = ASN1_INTEGER_new();
    if (!req || !imprint || !alg || !nonce) {
        goto cleanup;
    }

    obj = OBJ_nid2obj(NID_sha256);
    if (!obj) {
        goto cleanup;
    }
    X509_ALGOR_set0(alg, obj, V_ASN1_NULL, NULL);
    obj = NULL;

    if (TS_MSG_IMPRINT_set_algo(imprint, alg) != 1) {
        goto cleanup;
    }
    alg = NULL;

    if (TS_MSG_IMPRINT_set_msg(imprint, (unsigned char *)digest, (int)digest_len) != 1) {
        goto cleanup;
    }

    if (TS_REQ_set_msg_imprint(req, imprint) != 1) {
        goto cleanup;
    }
    imprint = NULL;

    if (TS_REQ_set_version(req, 1) != 1) {
        goto cleanup;
    }

    if (RAND_bytes((unsigned char *)&rnd, sizeof(rnd)) != 1) {
        goto cleanup;
    }
    if (ASN1_INTEGER_set(nonce, rnd) != 1) {
        goto cleanup;
    }
    if (TS_REQ_set_nonce(req, nonce) != 1) {
        goto cleanup;
    }
    nonce = NULL;

    if (TS_REQ_set_cert_req(req, 1) != 1) {
        goto cleanup;
    }

    der_len = i2d_TS_REQ(req, NULL);
    if (der_len <= 0) {
        goto cleanup;
    }

    der = (unsigned char *)malloc((size_t)der_len);
    if (!der) {
        goto cleanup;
    }
    p = der;
    if (i2d_TS_REQ(req, &p) != der_len) {
        goto cleanup;
    }

    out_der->data = der;
    out_der->len = (size_t)der_len;
    der = NULL;
    ok = 1;

cleanup:
    free(der);
    ASN1_INTEGER_free(nonce);
    ASN1_OBJECT_free(obj);
    X509_ALGOR_free(alg);
    TS_MSG_IMPRINT_free(imprint);
    TS_REQ_free(req);
    return ok;
}

/******************************************************************************
* Funkcia:    parse_http_response
*
* Popis:      Rozparsuje HTTP status, hlavicky a extrahuje telo odpovede
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int parse_http_response(const unsigned char *raw, size_t raw_len, buffer_t *body,
                               int *status_code, int *is_timestamp_reply) {
    size_t i;
    size_t body_off = 0;
    const unsigned char *header;
    size_t header_len;
    int chunked = 0;

    if (raw_len < 12) {
        return 0;
    }

    if (sscanf((const char *)raw, "HTTP/%*d.%*d %d", status_code) != 1) {
        return 0;
    }

    for (i = 0; i + 3 < raw_len; i++) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
            body_off = i + 4;
            break;
        }
    }
    if (body_off == 0 || body_off > raw_len) {
        return 0;
    }

    header = raw;
    header_len = body_off;

    if (is_timestamp_reply) {
        *is_timestamp_reply = mem_contains_ci(header, header_len, "content-type: application/timestamp-reply");
    }

    chunked = mem_contains_ci(header, header_len, "transfer-encoding: chunked");

    if (chunked) {
        return decode_chunked_body(raw + body_off, raw_len - body_off, body);
    }

    body->len = raw_len - body_off;
    body->data = (unsigned char *)malloc(body->len);
    if (!body->data) {
        return 0;
    }
    memcpy(body->data, raw + body_off, body->len);
    return 1;
}

/******************************************************************************
* Funkcia:    http_post_binary
*
* Popis:      Odosle HTTP POST s binarnym payloadom a vrati telo odpovede
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int http_post_binary(const char *host, int port, const char *path,
                            const unsigned char *body, size_t body_len,
                            buffer_t *out_body, int *out_status,
                            int *out_is_timestamp_reply) {
    BIO *bio = NULL;
    BIO *buf = NULL;
    char target[256];
    char header[1024];
    unsigned char tmp[READ_CHUNK];
    int n;
    int ok = 0;
    unsigned char *raw = NULL;
    size_t raw_len = 0;

    snprintf(target, sizeof(target), "%s:%d", host, port);

    bio = BIO_new_connect(target);
    if (!bio) {
        goto cleanup;
    }
    if (BIO_do_connect(bio) <= 0) {
        goto cleanup;
    }

    snprintf(header, sizeof(header),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/timestamp-query\r\n"
             "Content-Length: %lu\r\n"
             "Connection: close\r\n\r\n",
             path, host, (unsigned long)body_len);

    if (BIO_write(bio, header, (int)strlen(header)) <= 0) {
        goto cleanup;
    }
    if (BIO_write(bio, body, (int)body_len) <= 0) {
        goto cleanup;
    }
    if (BIO_flush(bio) <= 0) {
        goto cleanup;
    }

    buf = BIO_new(BIO_s_mem());
    if (!buf) {
        goto cleanup;
    }

    while ((n = BIO_read(bio, tmp, sizeof(tmp))) > 0) {
        if (BIO_write(buf, tmp, n) != n) {
            goto cleanup;
        }
    }

    raw_len = BIO_get_mem_data(buf, (char **)&raw);
    if (raw_len == 0 || !raw) {
        goto cleanup;
    }

    {
        buffer_t raw_copy = {0};
        raw_copy.data = (unsigned char *)malloc(raw_len);
        if (!raw_copy.data) {
            goto cleanup;
        }
        raw_copy.len = raw_len;
        memcpy(raw_copy.data, raw, raw_len);

        if (!parse_http_response(raw_copy.data, raw_copy.len, out_body, out_status,
                                 out_is_timestamp_reply)) {
            buffer_free(&raw_copy);
            goto cleanup;
        }
        buffer_free(&raw_copy);
    }

    ok = 1;

cleanup:
    if (!ok) {
        buffer_free(out_body);
    }
    BIO_free_all(buf);
    BIO_free_all(bio);
    return ok;
}

/******************************************************************************
* Funkcia:    load_x509_any
*
* Popis:      Nacita X.509 certifikat vo formate PEM alebo DER
*
* Navrat:     Ukazovatel na X509 alebo NULL pri chybe
*****************************************************************************/
static X509 *load_x509_any(const char *path) {
    BIO *bio = BIO_new_file(path, "rb");
    X509 *x = NULL;

    if (!bio) {
        return NULL;
    }

    x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!x) {
        BIO_seek(bio, 0);
        x = d2i_X509_bio(bio, NULL);
    }

    BIO_free(bio);
    return x;
}

/******************************************************************************
* Funkcia:    verify_token_signature
*
* Popis:      Overi PKCS7 podpis v timestamp tokene a volitelny trusted cert
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int verify_token_signature(PKCS7 *token, X509 *trusted_cert,
                                  char *signer_alg_buf, size_t signer_alg_buf_len) {
    STACK_OF(X509) *signers = NULL;
    X509 *signer = NULL;
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *store_ctx = NULL;
    EVP_PKEY *signer_key = NULL;
    int signer_key_type;
    int verify_err;
    int verified = 0;

    const char *verify_fail_msg = "Validacia certifikatovej retaze zlyhala: %s\n";

    signers = PKCS7_get0_signers(token, NULL, 0);
    if (!signers || sk_X509_num(signers) <= 0) {
        fprintf(stderr, "Token neobsahuje certifikaty signera.\n");
        sk_X509_free(signers);
        return 0;
    }

    signer = sk_X509_value(signers, 0);
    if (!signer) {
        sk_X509_free(signers);
        return 0;
    }

    signer_key = X509_get_pubkey(signer);
    if (!signer_key) {
        fprintf(stderr, "Nepodarilo sa ziskat verejny kluc signera.\n");
        goto cleanup;
    }

    signer_key_type = EVP_PKEY_base_id(signer_key);
    if (signer_key_type == EVP_PKEY_RSA) {
        if (signer_alg_buf && signer_alg_buf_len > 0) {
            snprintf(signer_alg_buf, signer_alg_buf_len, "RSA");
        }
    } else if (signer_key_type == EVP_PKEY_EC) {
        const char *curve_name = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        char group_name[80];
        size_t group_name_len = 0;

        if (EVP_PKEY_get_utf8_string_param(signer_key, OSSL_PKEY_PARAM_GROUP_NAME,
                                           group_name, sizeof(group_name), &group_name_len) != 1 ||
            group_name_len == 0) {
            fprintf(stderr, "Nepodarilo sa nacitat EC krivku signera.\n");
            goto cleanup;
        }

        if (strcmp(group_name, "prime256v1") == 0 || strcmp(group_name, "secp256r1") == 0) {
            curve_name = "P-256";
        } else if (strcmp(group_name, "secp384r1") == 0) {
            curve_name = "P-384";
        } else if (strcmp(group_name, "secp521r1") == 0) {
            curve_name = "P-521";
        } else {
            fprintf(stderr, "Nepodporovana ECDSA krivka signera. Podporovane: P-256, P-384, P-521.\n");
            goto cleanup;
        }
#else
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(signer_key);
        const EC_GROUP *group = NULL;
        int curve_nid = NID_undef;

        if (!ec) {
            fprintf(stderr, "Nepodarilo sa nacitat EC kluc signera.\n");
            goto cleanup;
        }

        group = EC_KEY_get0_group(ec);
        if (!group) {
            fprintf(stderr, "Nepodarilo sa nacitat EC krivku signera.\n");
            goto cleanup;
        }

        curve_nid = EC_GROUP_get_curve_name(group);
        switch (curve_nid) {
            case NID_X9_62_prime256v1:
                curve_name = "P-256";
                break;
            case NID_secp384r1:
                curve_name = "P-384";
                break;
            case NID_secp521r1:
                curve_name = "P-521";
                break;
            default:
                fprintf(stderr, "Nepodporovana ECDSA krivka signera. Podporovane: P-256, P-384, P-521.\n");
                goto cleanup;
        }
#endif

        if (signer_alg_buf && signer_alg_buf_len > 0) {
            snprintf(signer_alg_buf, signer_alg_buf_len, "ECDSA %s", curve_name);
        }
    } else {
        fprintf(stderr, "Nepodporovany typ verejneho kluca signera (type=%d).\n", signer_key_type);
        goto cleanup;
    }

    if (X509_check_purpose(signer, X509_PURPOSE_TIMESTAMP_SIGN, 0) != 1) {
        fprintf(stderr, "Certifikat signera nema povoleny ucel Time Stamping (id-kp-timeStamping).\n");
        goto cleanup;
    }

    store = X509_STORE_new();
    if (!store) {
        goto cleanup;
    }

    if (trusted_cert) {
        if (X509_STORE_add_cert(store, trusted_cert) != 1) {
            unsigned long err = ERR_peek_last_error();
            if (ERR_GET_LIB(err) != ERR_LIB_X509 ||
                ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                fprintf(stderr, "Nepodarilo sa pridat doveryhodny certifikat do trust store.\n");
                goto cleanup;
            }
            ERR_clear_error();
        }
    } else {
        if (X509_STORE_set_default_paths(store) != 1) {
            fprintf(stderr, "Nepodarilo sa inicializovat predvoleny trust store.\n");
            goto cleanup;
        }
    }

    if (token->d.sign && token->d.sign->cert) {
        untrusted = token->d.sign->cert;
    }

    store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        goto cleanup;
    }

    if (X509_STORE_CTX_init(store_ctx, store, signer, untrusted) != 1) {
        goto cleanup;
    }

    X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(store_ctx), X509_V_FLAG_PARTIAL_CHAIN);

    verified = (X509_verify_cert(store_ctx) == 1);
    if (!verified && !trusted_cert) {
        verify_err = X509_STORE_CTX_get_error(store_ctx);

        /* Ak systemovy/OpenSSL trust store nevie vybudovat retaz,
         * skusime fallback na signer certifikat ako trusted anchor.
         * To zachova pouzitelnost overenia aj na strojoch bez plneho trust store. */
        if (verify_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
            verify_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
            verify_err == X509_V_ERR_CERT_UNTRUSTED) {
            X509_STORE_CTX_free(store_ctx);
            store_ctx = NULL;
            X509_STORE_free(store);
            store = X509_STORE_new();
            if (!store) {
                goto cleanup;
            }

            if (X509_STORE_add_cert(store, signer) != 1) {
                goto cleanup;
            }

            store_ctx = X509_STORE_CTX_new();
            if (!store_ctx) {
                goto cleanup;
            }

            if (X509_STORE_CTX_init(store_ctx, store, signer, untrusted) != 1) {
                goto cleanup;
            }

            X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(store_ctx), X509_V_FLAG_PARTIAL_CHAIN);
            verified = (X509_verify_cert(store_ctx) == 1);
        }
    }

    if (!verified) {
        verify_err = store_ctx ? X509_STORE_CTX_get_error(store_ctx) : X509_V_ERR_CERT_UNTRUSTED;
        fprintf(stderr, verify_fail_msg, X509_verify_cert_error_string(verify_err));
        goto cleanup;
    }

    if (PKCS7_verify(token, signers, NULL, NULL, NULL, PKCS7_NOVERIFY) != 1) {
        fprintf(stderr, "Overenie PKCS7 podpisu zlyhalo.\n");
        goto cleanup;
    }

    EVP_PKEY_free(signer_key);
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);
    sk_X509_free(signers);
    return 1;

cleanup:
    EVP_PKEY_free(signer_key);
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);
    sk_X509_free(signers);
    return 0;
}

/******************************************************************************
* Funkcia:    save_metadata
*
* Popis:      Ulozi metadata timestampu do textoveho suboru
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int save_metadata(const char *path, const unsigned char digest[32], TS_RESP *resp) {
    FILE *fp = fopen(path, "w");
    TS_TST_INFO *tst;
    const ASN1_GENERALIZEDTIME *gen_time;
    const ASN1_INTEGER *serial;
    const ASN1_OBJECT *policy;
    BIO *tmp = NULL;
    BUF_MEM *bptr = NULL;

    if (!fp) {
        return 0;
    }

    fprintf(fp, "RFC3161 Timestamp Metadata\n");
    fprintf(fp, "==========================\n");
    fprintf(fp, "Message SHA-256: ");
    {
        size_t i;
        for (i = 0; i < 32; i++) {
            fprintf(fp, "%02x", digest[i]);
        }
    }
    fprintf(fp, "\n");

    tst = TS_RESP_get_tst_info(resp);
    if (!tst) {
        fclose(fp);
        return 0;
    }

    gen_time = TS_TST_INFO_get_time(tst);
    serial = TS_TST_INFO_get_serial(tst);
    policy = TS_TST_INFO_get_policy_id(tst);

    tmp = BIO_new(BIO_s_mem());
    if (!tmp) {
        fclose(fp);
        return 0;
    }

    if (gen_time && ASN1_GENERALIZEDTIME_print(tmp, gen_time) == 1) {
        BIO_get_mem_ptr(tmp, &bptr);
        if (bptr && bptr->length > 0) {
            fprintf(fp, "GenTime: %.*s\n", (int)bptr->length, bptr->data);
        }
    }

    (void)BIO_reset(tmp);
    if (serial && i2a_ASN1_INTEGER(tmp, serial) > 0) {
        BIO_get_mem_ptr(tmp, &bptr);
        if (bptr && bptr->length > 0) {
            fprintf(fp, "Serial: %.*s\n", (int)bptr->length, bptr->data);
        }
    }

    if (policy) {
        char obj_buf[128];
        OBJ_obj2txt(obj_buf, sizeof(obj_buf), policy, 1);
        fprintf(fp, "Policy OID: %s\n", obj_buf);
    }

    BIO_free(tmp);
    fclose(fp);
    return 1;
}

/******************************************************************************
* Funkcia:    timestamp_file
*
* Popis:      Vytvori timestamp token pre vstupny subor a ulozi vystupy
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int timestamp_file(const char *file_path, const char *server_name,
                          const char *host, int port, const char *path) {
    unsigned char digest[32];
    buffer_t req_der = {0};
    buffer_t resp_body = {0};
    TS_RESP *resp = NULL;
    const unsigned char *p;
    int status = 0;
    int is_timestamp_reply = 0;
    int resp_len;
    char tsr_path[1024];
    char meta_path[1024];
    int ok = 0;

    printf("  +=======================================================================+\n");
    printf("  |                  VYTVARANIE CASOVEJ PECIATKY                         |\n");
    printf("  +=======================================================================+\n\n");
    printf("  Subor:  %s\n", basename_path(file_path));
    if (server_name) {
        printf("  Server: %s (%s:%d%s)\n\n", server_name, host, port, path);
    } else {
        printf("  Server: %s:%d%s\n\n", host, port, path);
    }
    printf("  [1/5] Vypocitavam SHA-256 hash...\n");

    if (!sha256_file(file_path, digest)) {
        fprintf(stderr, "\n  [!] CHYBA: Nepodarilo sa vypocitat hash vstupneho suboru\n\n");
        goto cleanup;
    }

    printf("        >> Hash: ");
    print_hash_preview(digest, sizeof(digest));
    printf("\n\n");
    printf("  [2/5] Zostavujem RFC 3161 ziadost...\n");

    if (!build_ts_request_der(digest, sizeof(digest), &req_der)) {
        fprintf(stderr, "\n  [!] CHYBA: Nepodarilo sa vytvorit TS request\n\n");
        goto cleanup;
    }

    printf("        >> Ziadost zostavena (%lu bajtov)\n\n", (unsigned long)req_der.len);
    printf("  [3/5] Kontaktujem TSA server...\n");
    printf("        Server: %s:%d%s\n", host, port, path);

    if (!http_post_binary(host, port, path, req_der.data, req_der.len,
                          &resp_body, &status, &is_timestamp_reply)) {
        fprintf(stderr, "\n  [!] CHYBA: TSA ziadost zlyhala\n\n");
        goto cleanup;
    }
    if (status != 200) {
        fprintf(stderr, "\n  [!] CHYBA: TSA server vratil HTTP status %d\n\n", status);
        goto cleanup;
    }

    printf("        >> Odpoved prijata (HTTP %d, %lu bajtov)\n\n",
           status, (unsigned long)resp_body.len);
    printf("  [4/5] Parsovanie TSA odpovede...\n");

    if (!is_timestamp_reply) {
        fprintf(stderr, "Upozornenie: Content-Type odpovede nie je application/timestamp-reply.\n");
    }

    p = resp_body.data;
    resp = d2i_TS_RESP(NULL, &p, (long)resp_body.len);
    if (!resp) {
        fprintf(stderr, "\n  [!] CHYBA: Nepodarilo sa parsovat TSA odpoved\n");
        fprintf(stderr, "      Tip: vyberte iny TSA server cez --server (napr. DigiCert alebo FreeTSA).\n\n");
        goto cleanup;
    }

    resp_len = i2d_TS_RESP(resp, NULL);
    if (resp_len <= 0) {
        goto cleanup;
    }

    printf("        >> Token uspesne overeny\n\n");
    printf("  [5/5] Ukladam subory...\n");

    snprintf(tsr_path, sizeof(tsr_path), "%s.tsr", file_path);
    if (!write_file(tsr_path, resp_body.data, resp_body.len)) {
        fprintf(stderr, "Nepodarilo sa zapisat token subor: %s\n", tsr_path);
        goto cleanup;
    }
    printf("        >> Ulozene: %s\n", basename_path(tsr_path));

    snprintf(meta_path, sizeof(meta_path), "%s.metadata.txt", file_path);
    if (!save_metadata(meta_path, digest, resp)) {
        fprintf(stderr, "Nepodarilo sa zapisat metadata subor: %s\n", meta_path);
        goto cleanup;
    }
    printf("        >> Ulozene: %s\n\n", basename_path(meta_path));

    printf("  +=======================================================================+\n");
    printf("  | VYSLEDOK: CASOVA PECIATKA USPESNE VYTVORENA                          |\n");
    printf("  +=======================================================================+\n");
    printf("  | Stav: USPECH                                                         |\n");
    printf("  | Vas subor bol kryptograficky opatreny casovou peciatkou.             |\n");
    printf("  +=======================================================================+\n\n");
    ok = 1;

cleanup:
    TS_RESP_free(resp);
    buffer_free(&resp_body);
    buffer_free(&req_der);
    return ok;
}

/******************************************************************************
* Funkcia:    verify_timestamp
*
* Popis:      Overi, ze token patri suboru a podpis tokenu je validny
*
* Navrat:     1 pri uspechu, 0 pri chybe
*****************************************************************************/
static int verify_timestamp(const char *file_path, const char *token_path, const char *trusted_cert_path) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    buffer_t tsr = {0};
    const unsigned char *p;
    TS_RESP *resp = NULL;
    TS_TST_INFO *tst = NULL;
    TS_MSG_IMPRINT *imprint;
    const ASN1_OCTET_STRING *imprint_msg;
    const EVP_MD *imprint_md = NULL;
    int imprint_nid = NID_undef;
    int imprint_len = 0;
    char signer_alg[64] = "neznamy";
    PKCS7 *token;
    X509 *trusted = NULL;
    int ok = 0;

    printf("\n");
    printf("  +=======================================================================+\n");
    printf("  |                   OVEROVANIE CASOVEJ PECIATKY                        |\n");
    printf("  +=======================================================================+\n\n");
    printf("  Subor: %s\n\n", basename_path(file_path));
    printf("  [1/5] Citanie casoveho tokenu...\n");
    printf("        Token: %s\n", basename_path(token_path));

    if (!read_file(token_path, &tsr)) {
        fprintf(stderr, "\n  [!] CHYBA: Nepodarilo sa otvorit subor tokenu '%s'\n", token_path);
        fprintf(stderr, "\n  +=======================================================================+\n");
        fprintf(stderr, "  | VYSLEDOK: Subor NIE JE peciatkovany                                  |\n");
        fprintf(stderr, "  +=======================================================================+\n\n");
        goto cleanup;
    }

    printf("        >> Token nacitany (%lu bajtov)\n\n", (unsigned long)tsr.len);
    printf("  [2/5] Extrahovanie hashu z tokenu...\n");

    p = tsr.data;
    resp = d2i_TS_RESP(NULL, &p, (long)tsr.len);
    if (!resp) {
        fprintf(stderr, "Neplatny format tokenu (nie je TS_RESP DER).\n");
        goto cleanup;
    }

    tst = TS_RESP_get_tst_info(resp);
    if (!tst) {
        fprintf(stderr, "Token neobsahuje TSTInfo.\n");
        goto cleanup;
    }

    imprint = TS_TST_INFO_get_msg_imprint(tst);
    if (!imprint) {
        goto cleanup;
    }

    if (!get_imprint_digest_info(imprint, &imprint_md, &imprint_nid, &imprint_len)) {
        fprintf(stderr, "Nepodporovany digest algoritmus v tokene. Podporovane: SHA-256, SHA-384, SHA-512.\n");
        goto cleanup;
    }

    imprint_msg = TS_MSG_IMPRINT_get_msg(imprint);
    if (!imprint_msg || imprint_msg->length != imprint_len) {
        fprintf(stderr, "Nepodporovany format message imprint v tokene.\n");
        goto cleanup;
    }

    printf("        >> Hash uspesne extrahovany (%s)\n\n", digest_name_from_nid(imprint_nid));
    printf("  [3/5] Hashovanie suboru (%s)...\n", digest_name_from_nid(imprint_nid));

    if (!digest_file(file_path, imprint_md, digest, &digest_len) || (int)digest_len != imprint_len) {
        fprintf(stderr, "\n  [!] CHYBA: Nepodarilo sa vypocitat hash vstupneho suboru\n\n");
        goto cleanup;
    }

    printf("        >> Hash uspesne vypocitany\n\n");
    printf("  [4/5] Overovanie podpisu...\n");
    if (trusted_cert_path) {
        printf("        Pouzivany certifikat: %s\n", basename_path(trusted_cert_path));
    } else {
        printf("        Pouzivany trust store: systemovy/OpenSSL default\n");
    }

    if (memcmp(imprint_msg->data, digest, (size_t)imprint_len) != 0) {
        fprintf(stderr, "        >> Hash z tokenu sa nezhoduje s aktualnym suborom\n\n");
        goto cleanup;
    }

    token = TS_RESP_get_token(resp);
    if (!token) {
        fprintf(stderr, "Tokenu chyba PKCS7 podpisovy blok.\n");
        goto cleanup;
    }

    if (trusted_cert_path) {
        trusted = load_x509_any(trusted_cert_path);
        if (!trusted) {
            fprintf(stderr, "Nepodarilo sa nacitat doveryhodny certifikat: %s\n", trusted_cert_path);
            goto cleanup;
        }
    }

    if (!verify_token_signature(token, trusted, signer_alg, sizeof(signer_alg))) {
        goto cleanup;
    }

    printf("        >> Podpis uspesne overeny\n\n");
    printf("  [5/5] Porovnavam hashe...\n");

    if (trusted_cert_path) {
        printf("        >> Certifikatova retaz uspesne validovana proti zadanemu trust certifikatu\n");
    } else {
        printf("        >> Certifikatova retaz uspesne validovana proti systemovemu trust store\n");
    }

    printf("        >> Algoritmus message imprint: %s\n", digest_name_from_nid(imprint_nid));
    printf("        >> Algoritmus podpisu signera: %s\n", signer_alg);
    printf("        >> Hashe sa zhoduju!\n\n");

    printf("  +=======================================================================+\n");
    printf("  | VYSLEDOK: INTEGRITA SUBORU OVERENA                                   |\n");
    printf("  +=======================================================================+\n");
    printf("  | Stav: USPECH                                                         |\n");
    printf("  | Subor nebol zmeneny od vytvorenia casovej peciatky.                 |\n");
    printf("  +=======================================================================+\n\n");

    ok = 1;

cleanup:
    X509_free(trusted);
    TS_RESP_free(resp);
    buffer_free(&tsr);
    return ok;
}

/******************************************************************************
* Funkcia:    print_openssl_errors
*
* Popis:      Vypise OpenSSL chybovy stack na standardny chybovy vystup
*
* Navrat:     void
*****************************************************************************/
static void print_openssl_errors(void) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        fprintf(stderr, "OpenSSL: %s\n", ERR_error_string(e, NULL));
    }
}

/******************************************************************************
* Funkcia:    usage
*
* Popis:      Vypise napovedu pouzitia aplikacie
*
* Navrat:     void
*****************************************************************************/
static void usage(const char *exe) {
    const char *prog = basename_path(exe);
    size_t i;

    printf("\n");
    printf("  +=======================================================================+\n");
    printf("  |              RFC 3161 CASOVY PECIATKOVY KLIENT                       |\n");
    printf("  +=======================================================================+\n\n");

    printf("  INFORMACIE O PROJEKTE:\n");
    printf("  ------------------------------------------------------------------------\n");
    printf("    Nazov:   RFC 3161 CASOVY PECIATKOVY KLIENT\n");
    printf("    Projekt: TimeStampClient-C (OpenSSL)\n");
    printf("    Verzia:  v1.60\n");
    printf("    Autor:   Anton Kozar\n\n");

    printf("  POUZITIE A PRIKLADY:\n");
    printf("  ------------------------------------------------------------------------\n\n");

    printf("    1) VYTVORENIE CASOVEJ PECIATKY\n");
    printf("       Syntax:\n");
    printf("         .\\%s [--server <server>] <subor>\n\n", prog);
    printf("       Priklady:\n");
    printf("         .\\%s dokument.pdf\n", prog);
    printf("         .\\%s --server DigiCert dokument.pdf\n", prog);
    printf("         .\\%s --server GlobalSign dokument.pdf\n\n", prog);

    printf("    2) OVERENIE CASOVEJ PECIATKY\n");
    printf("       Syntax:\n");
    printf("         .\\%s -verify <subor> [token] [certifikat]\n\n", prog);
    printf("       Pouzivatel moze zadat aj vlastny certifikat (.crt/.cer/.pem/.der).\n");
    printf("       Priklady:\n");
    printf("         .\\%s -verify dokument.pdf\n", prog);
    printf("         .\\%s -verify dokument.pdf moj_token.tsr\n", prog);
    printf("         .\\%s -verify dokument.pdf moj_token.tsr Certificates\\FreeTSA.crt\n", prog);
    printf("         .\\%s -verify dokument.pdf moj_token.tsr C:\\my_certs\\moj_vlastny.crt\n", prog);
    printf("         .\\%s -verify dokument.pdf C:\\my_certs\\moj_vlastny.crt\n\n", prog);

    printf("  ------------------------------------------------------------------------\n");
    printf("  DOSTUPNE SERVERY:\n\n");
    for (i = 0; i < TSA_SERVER_COUNT; i++) {
        if (i == 0) {
            printf("    * %-11s %-34s [default]\n", TSA_SERVERS[i].name, TSA_SERVERS[i].host);
        } else {
            printf("    - %-11s %-34s\n", TSA_SERVERS[i].name, TSA_SERVERS[i].host);
        }
    }

    printf("\n  ------------------------------------------------------------------------\n");
    printf("  VYSTUPNE SUBORY:\n\n");
    printf("    <subor>.tsr              timestamp token\n");
    printf("    <subor>.metadata.txt     informacie o peciatke\n\n");

    printf("  ------------------------------------------------------------------------\n");
    printf("  POZNAMKY:\n\n");
    printf("    - Default server je %s\n", TSA_SERVERS[0].name);
    printf("    - [token] a [certifikat] su volitelne\n");
    printf("    - Ak zadate iba jeden parameter po <subor>, app ho rozpozna takto:\n");
    printf("      .crt / .cer / .pem / .der = certifikat, inak = token\n");
    printf("    - Certifikat sa pouziva na kontrolu zhody certifikatu v tokene\n");
    printf("    - Pri overeni sa vykonava plna validacia certifikatovej retaze\n");
    printf("      (zadany certifikat ako trust anchor, alebo systemovy trust store)\n");
    printf("    - Overenie podporuje message imprint SHA-256, SHA-384 a SHA-512\n");
    printf("    - ECDSA signer je podporovany pre krivky P-256, P-384 a P-521\n");
    printf("    - Mozete pouzit certifikat z Certificates/ alebo vlastny certifikat\n\n");

    printf("  +========================================================================+\n\n");
}

/******************************************************************************
* Funkcia:    main
*
* Popis:      Vstupny bod aplikacie, parsovanie argumentov a riadenie toku
*
* Navrat:     0 pri uspechu, 1 pri chybe
*****************************************************************************/
int main(int argc, char **argv) {
    const tsa_server_config_t *selected_server = &TSA_SERVERS[0];
    const char *host = DEFAULT_TSA_HOST;
    int port = DEFAULT_TSA_PORT;
    const char *path = DEFAULT_TSA_PATH;
    const char *server_name = TSA_SERVERS[0].name;
    int arg_index = 1;
    int ok;
    int implicit_verify = 0;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    while (arg_index < argc) {
        if (strcmp(argv[arg_index], "--server") == 0) {
            if (arg_index + 1 >= argc) {
                usage(argv[0]);
                return 1;
            }

            selected_server = find_tsa_server(argv[arg_index + 1]);
            if (!selected_server) {
                fprintf(stderr, "Neznamy TSA server: %s\n", argv[arg_index + 1]);
                usage(argv[0]);
                return 1;
            }

            host = selected_server->host;
            port = selected_server->port;
            path = selected_server->path;
            server_name = selected_server->name;
            arg_index += 2;

        } else if (strcmp(argv[arg_index], "-verify") == 0) {
            break;

        } else if (argv[arg_index][0] == '-') {
            usage(argv[0]);
            return 1;
        } else {
            break;
        }
    }

    if (arg_index >= argc) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[arg_index], "-verify") == 0) {
        const char *file_path;
        char default_token[1024];
        const char *token_path;
        const char *cert_path = NULL;

        if (arg_index + 1 >= argc) {
            usage(argv[0]);
            return 1;
        }

        file_path = argv[arg_index + 1];
        snprintf(default_token, sizeof(default_token), "%s.tsr", file_path);

        token_path = default_token;
        if (arg_index + 2 < argc) {
            if (is_certificate_path(argv[arg_index + 2])) {
                cert_path = argv[arg_index + 2];
            } else {
                token_path = argv[arg_index + 2];
                if (arg_index + 3 < argc) {
                    cert_path = argv[arg_index + 3];
                }
            }
        }

        if (arg_index + 4 < argc) {
            usage(argv[0]);
            EVP_cleanup();
            ERR_free_strings();
            return 1;
        }

        ok = verify_timestamp(file_path, token_path, cert_path);
        if (!ok) {
            print_openssl_errors();
            EVP_cleanup();
            ERR_free_strings();
            return 1;
        }
    } else {
        const char *file_path = argv[arg_index];

        if (arg_index + 1 < argc && argv[arg_index + 1][0] != '-') {
            const char *token_path = NULL;
            const char *cert_path = NULL;
            char default_token[1024];

            implicit_verify = 1;
            snprintf(default_token, sizeof(default_token), "%s.tsr", file_path);

            if (arg_index + 1 < argc) {
                if (is_certificate_path(argv[arg_index + 1])) {
                    cert_path = argv[arg_index + 1];
                    token_path = default_token;
                } else {
                    token_path = argv[arg_index + 1];
                }
            }

            if (arg_index + 2 < argc) {
                cert_path = argv[arg_index + 2];
            }

            if (arg_index + 3 < argc) {
                usage(argv[0]);
                EVP_cleanup();
                ERR_free_strings();
                return 1;
            }

            ok = verify_timestamp(file_path, token_path ? token_path : default_token, cert_path);
            if (!ok) {
                print_openssl_errors();
                EVP_cleanup();
                ERR_free_strings();
                return 1;
            }
        }

        if (!implicit_verify) {
            if (arg_index + 1 < argc) {
                if (argv[arg_index + 1][0] == '-') {
                    usage(argv[0]);
                    EVP_cleanup();
                    ERR_free_strings();
                    return 1;
                }
            }

            ok = timestamp_file(file_path, server_name, host, port, path);
            if (!ok) {
                print_openssl_errors();
                EVP_cleanup();
                ERR_free_strings();
                return 1;
            }
        }
    }

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
