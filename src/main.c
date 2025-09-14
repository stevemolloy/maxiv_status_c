#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"

#define HOST "status.maxiv.lu.se"
#define PATH "/stream"
#define URL "https://"HOST PATH
#define PORT "443"

#define RESP_BUFF_LEN 65536
char buffer[RESP_BUFF_LEN];

int main(void) {
    const char *host = HOST;

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        nob_log(ERROR, "Socket creation error");
        return 1;
    }

    struct addrinfo hints = {
        .ai_flags = AI_NUMERICHOST | AI_CANONNAME,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    struct addrinfo *addr = NULL;

    int retval = getaddrinfo(host, PORT, &hints, &addr);
    if (retval == EAI_NONAME) {
        hints.ai_flags = 0 | AI_CANONNAME;
        retval = getaddrinfo(host, PORT, &hints, &addr);
    }

    if (retval != 0) {
        nob_log(ERROR, "Couldn't get IP info on the URL: %s", host);
        return 1;
    }

    char ip_str[NI_MAXHOST];
    int result = getnameinfo(
        addr->ai_addr,
        addr->ai_addrlen,
        ip_str,
        NI_MAXHOST,
        NULL,
        0,
        NI_NUMERICHOST
    );

    if (result != 0) {
        nob_log(ERROR, "Could not get IP string from URL info");
        freeaddrinfo(addr);
        return 1;
    }

    nob_log(INFO, "IP address of %s is %s", host, ip_str);

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        nob_log(ERROR, "Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (connect(client_fd, addr->ai_addr, addr->ai_addrlen) < 0) {
        nob_log(ERROR, "Unable to connect to %s (%s)", host, ip_str);
        freeaddrinfo(addr);
        return 1;
    }

    nob_log(INFO, "Connected successfully to %s (%s)", host, ip_str);

    // Create SSL connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    // Set hostname for SNI (Server Name Indication)
    SSL_set_tlsext_host_name(ssl, host);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        nob_log(ERROR, "SSL connection failed");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        freeaddrinfo(addr);
        SSL_CTX_free(ctx);
        close(client_fd);
        return 1;
    }

    nob_log(INFO, "SSL connection established successfully");

    char http_request[1024];
    snprintf(http_request, sizeof(http_request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        PATH,
        host
    );

    // Send request via SSL
    if (SSL_write(ssl, http_request, strlen(http_request)) <= 0) {
        nob_log(ERROR, "Failed to send HTTPS request");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        freeaddrinfo(addr);
        SSL_CTX_free(ctx);
        close(client_fd);
        return 1;
    }

    nob_log(INFO, "Sent data to %s (%s)", host, ip_str);

    ssize_t bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0) {
        nob_log(INFO, "Received %ld bytes", bytes_received);
        buffer[bytes_received] = '\0';
        printf("Response:\n%s\n", buffer);
    } else {
        nob_log(INFO, "Received %ld bytes", bytes_received);
    }

    freeaddrinfo(addr);
    close(client_fd);

	return 0;
}
