#include <stdbool.h>
#include <openssl/err.h>
#include <netdb.h>

#define NOB_STRIP_PREFIX
#include "nob.h"
#include "lib.h"

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

bool get_ip_str(const char* host, const char *port, struct addrinfo **addr, char **ip_str) {
    struct addrinfo hints = {
        .ai_flags = AI_CANONNAME,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    int retval = getaddrinfo(host, port, &hints, addr);

    if (retval != 0) {
        nob_log(ERROR, "Couldn't get IP info on the URL: %s", host);
        return false;
    }

    int gni_result = getnameinfo(
        (*addr)->ai_addr,
        (*addr)->ai_addrlen,
        *ip_str,
        NI_MAXHOST,
        NULL,
        0,
        NI_NUMERICHOST
    );

    if (gni_result != 0) {
        nob_log(ERROR, "Could not get IP string from URL info");
        return false;
    }

    return true;
}

bool prep_SSL_connection(SSL_CTX *ctx, SSL **ssl, int client_fd, const char *host) {
    // Create SSL connection
    *ssl = SSL_new(ctx);
    SSL_set_fd(*ssl, client_fd);

    // Set hostname for SNI (Server Name Indication)
    SSL_set_tlsext_host_name(*ssl, host);

    // Perform SSL handshake
    if (SSL_connect(*ssl) <= 0) {
        nob_log(ERROR, "SSL connection failed");
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

