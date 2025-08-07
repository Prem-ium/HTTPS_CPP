// server.cpp
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include <cstring>

int main() {
    mbedtls_net_context srv, cli;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config cfg;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    const char *pers = "https_server";

    mbedtls_net_init(&srv); mbedtls_net_init(&cli);
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&cfg);
    mbedtls_x509_crt_init(&cert); mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&rng);

    mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    mbedtls_x509_crt_parse_file(&cert, "cert.pem");
    mbedtls_pk_parse_keyfile(&key, "key.pem", 0);

    mbedtls_ssl_config_defaults(&cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&cfg, mbedtls_ctr_drbg_random, &rng);
    mbedtls_ssl_conf_ca_chain(&cfg, cert.next, 0);
    mbedtls_ssl_conf_own_cert(&cfg, &cert, &key);
    mbedtls_ssl_setup(&ssl, &cfg);

    mbedtls_net_bind(&srv, 0, "4433", MBEDTLS_NET_PROTO_TCP);
    mbedtls_net_accept(&srv, &cli, 0, 0, 0);
    mbedtls_ssl_set_bio(&ssl, &cli, mbedtls_net_send, mbedtls_net_recv, 0);
    mbedtls_ssl_handshake(&ssl);

    char buf[1024];
    mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf));
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, HTTPS!";
    mbedtls_ssl_write(&ssl, (const unsigned char*)resp, strlen(resp));

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&cli); mbedtls_net_free(&srv);
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&cfg);
    mbedtls_x509_crt_free(&cert); mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&rng); mbedtls_entropy_free(&entropy);
}
