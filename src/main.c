#include <alloca.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"

#include "lib.h"

#define SPF_ATTR_NAME "I-SP02/DIA/CT-02/AVERAGECHARGE"
#define R1_ATTR_NAME  "R1-101S/DIA/DCCT-01/CURRENT"
#define R3_ATTR_NAME  "R3-319S2/DIA/DCCT-01/CURRENT"

#define HOST "status.maxiv.lu.se"
#define PATH "/stream"
#define URL "https://"HOST PATH
#define PORT "443"

#define HTTP_REQUEST "GET "PATH" HTTP/1.1\r\nHost: "HOST"\r\nConnection: close\r\n\r\n"

#define RESP_BUFF_LEN 65536
static char buffer[RESP_BUFF_LEN] = {0};

int main(void) {
    int result = 0;
    struct addrinfo *addr = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        nob_log(ERROR, "Socket creation error");
        return_defer(1);
    }

    char *ip_str = alloca(NI_MAXHOST);
    memset(ip_str, 0, NI_MAXHOST);
    if (!get_ip_str(HOST, PORT, &addr, &ip_str)) return_defer(1);

    if (connect(client_fd, addr->ai_addr, addr->ai_addrlen) < 0) {
        nob_log(ERROR, "Unable to connect to %s (%s)", HOST, ip_str);
        return_defer(1);
    }

    // Initialize OpenSSL
    if (!init_openssl(&ctx)) return_defer(1);
    if (!prep_SSL_connection(ctx, &ssl, client_fd, HOST)) return_defer(1);

    // Send request via SSL
    if (SSL_write(ssl, HTTP_REQUEST, strlen(HTTP_REQUEST)) <= 0) {
        nob_log(ERROR, "Failed to send HTTPS request");
        ERR_print_errors_fp(stderr);
        return_defer(1);
    }

    int try_counter = 0;
    ssize_t bytes_received = SSL_read(ssl, buffer, RESP_BUFF_LEN - 1);
    while (bytes_received < 2048 && try_counter++ < 10) {
        if (bytes_received < 0) {
            nob_log(ERROR, "Cannot read from site");
            return_defer(1);
        }
        bytes_received = SSL_read(ssl, buffer, RESP_BUFF_LEN - 1);
    }

    if (bytes_received < 2048) {
        nob_log(ERROR, "Reading from the site succeeded, but the required data did not arrive");
        return_defer(1);
    }

    double r3_value, r1_value, spf_value;
    if (!extract_value(buffer, R3_ATTR_NAME, &r3_value)) return_defer(1);
    if (!extract_value(buffer, R1_ATTR_NAME, &r1_value)) return_defer(1);
    if (!extract_value(buffer, SPF_ATTR_NAME, &spf_value)) return_defer(1);
    printf("| R3 %0.1f mA | R1 %0.1f mA | SPF %0.1f pC\n", r3_value*1e3, r1_value*1e3, spf_value*1e12);

defer:
    if (addr != NULL) freeaddrinfo(addr);
    if (client_fd != 0) close(client_fd);
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
	return result;
}

