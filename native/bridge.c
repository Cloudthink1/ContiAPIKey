#include <stdlib.h>
#include <stdint.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>

#if MBEDTLS_VERSION_NUMBER != 0x03060800
#error This bridge requires Mbed TLS 3.6.8
#endif

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt roots;
    mbedtls_ctr_drbg_context rng;
    mbedtls_entropy_context entropy;
} apdu_tls;

__declspec(dllexport) void apdu_tls_free(apdu_tls *tls) {
    if (tls == NULL) return;
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->config);
    mbedtls_x509_crt_free(&tls->roots);
    mbedtls_ctr_drbg_free(&tls->rng);
    mbedtls_entropy_free(&tls->entropy);
    free(tls);
}

__declspec(dllexport) int apdu_tls_create(
    apdu_tls **out, const char *hostname, const unsigned char *roots, size_t size,
    void *socket, mbedtls_ssl_send_t *send_fn, mbedtls_ssl_recv_t *recv_fn) {
    static const char *protocols[] = {"http/1.1", NULL};
    apdu_tls *tls = calloc(1, sizeof(*tls));
    int rc = MBEDTLS_ERR_SSL_ALLOC_FAILED;
    if (tls == NULL) return rc;
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->config);
    mbedtls_x509_crt_init(&tls->roots);
    mbedtls_ctr_drbg_init(&tls->rng);
    mbedtls_entropy_init(&tls->entropy);

    while (size >= 4) {
        size_t len = ((size_t) roots[0] << 24) | ((size_t) roots[1] << 16)
                   | ((size_t) roots[2] << 8) | roots[3];
        roots += 4;
        size -= 4;
        if (len == 0 || len > size) { rc = MBEDTLS_ERR_SSL_BAD_INPUT_DATA; goto failed; }
        rc = mbedtls_x509_crt_parse_der(&tls->roots, roots, len);
        if (rc != 0) goto failed;
        roots += len;
        size -= len;
    }
    if (size != 0 || tls->roots.version == 0) { rc = MBEDTLS_ERR_SSL_BAD_INPUT_DATA; goto failed; }
    rc = mbedtls_ctr_drbg_seed(&tls->rng, mbedtls_entropy_func, &tls->entropy,
                               (const unsigned char *) "codex-apdu-deepseek", 19);
    if (rc != 0) goto failed;
    rc = mbedtls_ssl_config_defaults(&tls->config, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) goto failed;
    mbedtls_ssl_conf_min_tls_version(&tls->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&tls->config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(&tls->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&tls->config, &tls->roots, NULL);
    mbedtls_ssl_conf_rng(&tls->config, mbedtls_ctr_drbg_random, &tls->rng);
    rc = mbedtls_ssl_conf_alpn_protocols(&tls->config, protocols);
    if (rc != 0) goto failed;
    rc = mbedtls_ssl_setup(&tls->ssl, &tls->config);
    if (rc != 0) goto failed;
    rc = mbedtls_ssl_set_hostname(&tls->ssl, hostname);
    if (rc != 0) goto failed;
    mbedtls_ssl_set_bio(&tls->ssl, socket, send_fn, recv_fn, NULL);
    *out = tls;
    return 0;
failed:
    apdu_tls_free(tls);
    return rc;
}

__declspec(dllexport) int apdu_tls_handshake(apdu_tls *tls) {
    int rc = mbedtls_ssl_handshake(&tls->ssl);
    if (rc == 0 && mbedtls_ssl_get_verify_result(&tls->ssl) != 0)
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return rc;
}

__declspec(dllexport) int apdu_tls_read(apdu_tls *tls, unsigned char *buf, size_t len) {
    int rc;
    do { rc = mbedtls_ssl_read(&tls->ssl, buf, len); }
    while (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET);
    return rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? 0 : rc;
}

__declspec(dllexport) int apdu_tls_write(apdu_tls *tls, const unsigned char *buf, size_t len) {
    return mbedtls_ssl_write(&tls->ssl, buf, len);
}

__declspec(dllexport) int apdu_tls_close(apdu_tls *tls) {
    return mbedtls_ssl_close_notify(&tls->ssl);
}
