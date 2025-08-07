// mbedtls_https_server.cpp
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/error.h>

#define SERVER_PORT "4433"

int main() {
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "ssl_server";

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed RNG
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char*)pers, strlen(pers));

    // Load cert/key
    mbedtls_x509_crt_parse_file(&cert, "cert.pem");
    mbedtls_pk_parse_keyfile(&pkey, "key.pem", nullptr);

    // Bind to port
    mbedtls_net_bind(&listen_fd, nullptr, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);

    // SSL config
    mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&conf, cert.next, nullptr);
    mbedtls_ssl_conf_own_cert(&conf, &cert, &pkey);
    mbedtls_ssl_setup(&ssl, &conf);

    std::cout << "Waiting for client on port " << SERVER_PORT << "...\n";
    mbedtls_net_accept(&listen_fd, &client_fd, nullptr, 0, nullptr);
    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    if (mbedtls_ssl_handshake(&ssl) != 0) {
        std::cerr << "TLS handshake failed\n";
    } else {
        char buffer[1024];
        mbedtls_ssl_read(&ssl, (unsigned char*)buffer, sizeof(buffer) - 1);
        const char* resp =
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, HTTPS!";
        mbedtls_ssl_write(&ssl, (const unsigned char*)resp, strlen(resp));
    }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
