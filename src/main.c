#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"

#define SPF_ATTR_NAME "I-SP02/DIA/CT-02/AVERAGECHARGE"
#define R1_ATTR_NAME  "R1-101S/DIA/DCCT-01/CURRENT"
#define R3_ATTR_NAME  "R3-319S2/DIA/DCCT-01/CURRENT"

#define HOST "status.maxiv.lu.se"
#define PATH "/stream"
#define URL "https://"HOST PATH
#define PORT "443"

#define RESP_BUFF_LEN 65536
static char buffer[RESP_BUFF_LEN] = {0};

bool extract_value(const char *fulldata, const char*searchstr, double *val);
bool init_openssl(SSL_CTX **ctx);

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

    struct addrinfo hints = {
        .ai_flags = 0 | AI_CANONNAME,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    int retval = getaddrinfo(HOST, PORT, &hints, &addr);

    if (retval != 0) {
        nob_log(ERROR, "Couldn't get IP info on the URL: %s", HOST);
        return_defer(1);
    }

    char ip_str[NI_MAXHOST];
    int gni_result = getnameinfo(
        addr->ai_addr,
        addr->ai_addrlen,
        ip_str,
        NI_MAXHOST,
        NULL,
        0,
        NI_NUMERICHOST
    );

    if (gni_result != 0) {
        nob_log(ERROR, "Could not get IP string from URL info");
        return_defer(1);
    }

    // Initialize OpenSSL
    if (!init_openssl(&ctx)) return_defer(1);

    if (connect(client_fd, addr->ai_addr, addr->ai_addrlen) < 0) {
        nob_log(ERROR, "Unable to connect to %s (%s)", HOST, ip_str);
        return_defer(1);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    // Set hostname for SNI (Server Name Indication)
    SSL_set_tlsext_host_name(ssl, HOST);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        nob_log(ERROR, "SSL connection failed");
        ERR_print_errors_fp(stderr);
        return_defer(1);
    }

    char http_request[1024];
    snprintf(http_request, sizeof(http_request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        PATH,
        HOST
    );

    // Send request via SSL
    if (SSL_write(ssl, http_request, strlen(http_request)) <= 0) {
        nob_log(ERROR, "Failed to send HTTPS request");
        ERR_print_errors_fp(stderr);
        return_defer(1);
    }

    int try_counter = 0;
    ssize_t bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    while (bytes_received < 2048 && try_counter < 10) {
        try_counter++;
        if (bytes_received < 0) {
            nob_log(ERROR, "Cannot read from site");
            return_defer(1);
        }
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    }
    if (bytes_received < 2048) {
        nob_log(ERROR, "Reading from the site succeeded, but the required data did not arrive");
        return_defer(1);
    }

    double r3_value, r1_value, spf_value;
    if (!extract_value(buffer, R3_ATTR_NAME, &r3_value)) return_defer(1);
    if (!extract_value(buffer, R1_ATTR_NAME, &r1_value)) return_defer(1);
    if (!extract_value(buffer, SPF_ATTR_NAME, &spf_value)) return_defer(1);
    printf("| R3 %0.1f mA | ", r3_value * 1000);
    printf("R1 %0.1f mA | ", r1_value * 1000);
    printf("SPF %0.1f pC\n", spf_value * 1000 * 1000 * 1000 * 1000);

defer:
    if (addr != NULL) freeaddrinfo(addr);
    if (client_fd != 0) close(client_fd);
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
	return result;
}

bool extract_value(const char *fulldata, const char*searchstr, double *val) {
    const char *start = strstr(fulldata, searchstr);
    if (start == NULL) {
        nob_log(ERROR, "Could not find \"%s\" in the data", searchstr);
        return false;
    }
    char *value_str = strstr(start, "\"value\"");
    if (value_str == NULL) {
        nob_log(ERROR, "Could not find an associated \"value\" node in the data");
        return false;
    }
    if (strlen(value_str) < 9) {
        nob_log(ERROR, "It appears that the transmisison was cut short");
        return false;
    }
    value_str += 7;
    while (strlen(value_str) > 0 && (value_str[0]==':' || value_str[0]==' ')) {
        value_str++;
    }
    char *endptr;
    *val = strtod(value_str, &endptr);
    if (endptr == value_str) {
        nob_log(ERROR, "Could not find a numerical value associated with \"%s\"", searchstr);
        return false;
    }

    return true;
}

bool init_openssl(SSL_CTX **ctx) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    *ctx = SSL_CTX_new(method);
    if (!(*ctx)) {
        nob_log(ERROR, "Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

