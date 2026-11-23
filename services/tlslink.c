/* TLS for the services <-> hub link ([link] tls = true in services.toml): what lets the daemon run on another machine than
 * the hub without IDENTIFY / SASL passwords crossing the network in the clear. The hub side needs nothing new -- its link
 * listener has always accepted TLS (plain text only from loopback when [links] tls is on).
 *
 * The hub's certificate is judged one of two ways, like a leaf judges its hub (src/link.c dial_peer): pinned by its SHA-256
 * fingerprint (the chain is ignored, the fingerprint decides, checked BEFORE the password is sent), or verified like a web
 * server's -- against ca_file or the system CAs, and for the name or address in [link] host. A client certificate
 * (cert/key) is optional: it is what lets the hub pin this daemon with a fingerprint on its [[links.peers]] entry. */
#include "svc.h"
#include "../src/crypto.h"
#include "../src/log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <sys/socket.h>

/* A pinned link never trusts the chain: the fingerprint is checked once connected. */
static int accept_any_cert(int preverify_ok, X509_STORE_CTX *ctx) { (void)preverify_ok; (void)ctx; return 1; }

int svc_tls_cfg_equal(const svc_tls_cfg_t *a, const svc_tls_cfg_t *b) {
    return a->enabled == b->enabled && a->require == b->require && !strcmp(a->fingerprint, b->fingerprint) && !strcmp(a->ca_file, b->ca_file) &&
           !strcmp(a->cert, b->cert) && !strcmp(a->key, b->key);
}

static void ssl_error(const char *what, const char *host, SSL *ssl) {
    char e[256];
    ERR_error_string_n(ERR_get_error(), e, sizeof e);
    long v = ssl ? SSL_get_verify_result(ssl) : X509_V_OK;
    if (v != X509_V_OK) log_warn("services", "%s %s failed: %s (%s)", what, host, e, X509_verify_cert_error_string(v));
    else log_warn("services", "%s %s failed: %s", what, host, e);
}

SSL *svc_tls_connect(int fd, const char *host, const svc_tls_cfg_t *c) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ERR_clear_error();
    if (c->ca_file[0] ? SSL_CTX_load_verify_locations(ctx, c->ca_file, NULL) != 1 : SSL_CTX_set_default_verify_paths(ctx) != 1) {
        ssl_error("loading the CA certificates for", host, NULL);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (c->cert[0] && (SSL_CTX_use_certificate_chain_file(ctx, c->cert) != 1 || SSL_CTX_use_PrivateKey_file(ctx, c->key, SSL_FILETYPE_PEM) != 1 ||
                       SSL_CTX_check_private_key(ctx) != 1)) {
        ssl_error("loading the client certificate for", host, NULL);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx); /* the SSL keeps its own reference */
    if (!ssl) return NULL;
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER); /* the send buffer moves between retries */
    SSL_set_fd(ssl, fd);

    struct in_addr a4;
    struct in6_addr a6;
    int is_ip = inet_pton(AF_INET, host, &a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1;
    if (!is_ip) SSL_set_tlsext_host_name(ssl, host); /* SNI: never for an address literal */
    if (c->fingerprint[0]) SSL_set_verify(ssl, SSL_VERIFY_PEER, accept_any_cert);
    else {
        SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
        if (is_ip) X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host);
        else SSL_set1_host(ssl, host); /* the certificate must be for this name, not merely trusted */
    }
    ERR_clear_error();
    if (SSL_connect(ssl) != 1) {
        ssl_error("TLS handshake to", host, ssl);
        SSL_free(ssl);
        return NULL;
    }
    if (c->fingerprint[0]) { /* before PASS: never hand the link password to the wrong server */
        char got[65];
        if (crypto_peer_fingerprint(ssl, got, sizeof got) != 0) {
            log_warn("services", "hub %s presented no TLS certificate, but its fingerprint is pinned", host);
            SSL_free(ssl);
            return NULL;
        }
        if (strcmp(got, c->fingerprint) != 0) {
            log_warn("services", "hub %s presented certificate sha256:%s, not the pinned sha256:%s -- not sending the password", host, got, c->fingerprint);
            SSL_free(ssl);
            return NULL;
        }
    }
    log_info("services", "TLS established to %s (%s/%s)%s", host, SSL_get_version(ssl), SSL_get_cipher_name(ssl),
             c->fingerprint[0] ? ", certificate pinned" : ", certificate verified");
    return ssl;
}

/* read/write(2) semantics for a non-blocking socket: >0 bytes, 0 on a clean close, -1 with errno = EAGAIN when it would
 * block (either way: TLS can need to write to read), -1 otherwise. */
ssize_t svc_tls_read(SSL *ssl, void *buf, size_t len) {
    ERR_clear_error();
    int n = SSL_read(ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

ssize_t svc_tls_write(SSL *ssl, const void *buf, size_t len) {
    ERR_clear_error();
    int n = SSL_write(ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

int svc_tls_pending(SSL *ssl) { return ssl && SSL_pending(ssl) > 0; }

void svc_tls_close(SSL *ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl); /* best effort: a close_notify if the socket takes it */
    SSL_free(ssl);
}
