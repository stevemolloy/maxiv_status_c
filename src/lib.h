#ifndef _LIB_H
#define _LIB_H
#include <openssl/ssl.h>

bool extract_value(const char *fulldata, const char*searchstr, double *val);
bool init_openssl(SSL_CTX **ctx);
bool get_ip_str(const char* host, const char *port, struct addrinfo **addr, char **ip_str);
bool prep_SSL_connection(SSL_CTX *ctx, SSL **ssl, int client_fd, const char *host);

#endif // _LIB_H

