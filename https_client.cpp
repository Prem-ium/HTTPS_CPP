// mbedtls_https_client.cpp
#include <iostream>
#include <cstring>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#define SERVER_PORT "4433"
#define SERVER_ADDR "127.0.0.1"

int main() {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "ssl_client";

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char*)pers, strlen(pers));

    mbedtls_net_connect(&server_fd, SERVER_ADDR, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);

    mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

    if (mbedtls_ssl_handshake(&ssl) != 0) {
        std::cerr << "Handshake failed\n";
        return 1;
    }

    const char* req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    mbedtls_ssl_write(&ssl, (const unsigned char*)req, strlen(req));

    char buffer[1024];
    int len = mbedtls_ssl_read(&ssl, (unsigned char*)buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        std::cout << "Server Response:\n" << buffer << std::endl;
    }

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
