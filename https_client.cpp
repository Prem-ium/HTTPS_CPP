// client.cpp
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <cstring>
#include <cstdio>

int main() {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config cfg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    const char *pers = "https_client";

    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&cfg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);

    mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    mbedtls_net_connect(&net, "127.0.0.1", "4433", MBEDTLS_NET_PROTO_TCP);

    mbedtls_ssl_config_defaults(&cfg, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&cfg, MBEDTLS_SSL_VERIFY_NONE); // skip cert verify
    mbedtls_ssl_conf_rng(&cfg, mbedtls_ctr_drbg_random, &rng);
    mbedtls_ssl_setup(&ssl, &cfg);
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, 0);
    mbedtls_ssl_handshake(&ssl);

    const char *req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    mbedtls_ssl_write(&ssl, (const unsigned char*)req, strlen(req));
    char buf[1024];
    int len = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf)-1);
    if (len > 0) { buf[len] = 0; puts(buf); }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&net); mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&cfg); mbedtls_ctr_drbg_free(&rng); mbedtls_entropy_free(&entropy);
}
