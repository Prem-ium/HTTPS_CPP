#define _WIN32_WINNT 0x0601
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32 // If compiling on Windows
#include <winsock2.h>
#include <ws2tcpip.h>  // inet_pton
#pragma comment(lib, "ws2_32.lib") 
#else // If compiling Unix-like systems
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif


#define HOST "127.0.0.1"
#define PORT 4433

int main() {
#ifdef _WIN32 //  declare Winsock; if windows
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif 

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
#ifdef _WIN32
    if (inet_pton(AF_INET, HOST, &addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported\n";
        return 1;
    }
#else
    inet_aton(HOST, &addr.sin_addr);
#endif


    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        const char* req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        SSL_write(ssl, req, strlen(req));

        char buffer[4096];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::cout << "Received:\n" << buffer << std::endl;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
