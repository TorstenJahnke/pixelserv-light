/*
 * test_openssl_fetch.c - Test HTTPS fetch with pure OpenSSL (no libcurl)
 * Compile: gcc -o test_openssl_fetch test_openssl_fetch.c -lssl -lcrypto
 * Run: ./test_openssl_fetch
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096

typedef struct {
    int status_code;
    char content_type[256];
    char *body;
    size_t body_len;
    char error[256];
} fetch_response_t;

/* Connect to host:port and return socket fd */
static int tcp_connect(const char *host, int port) {
    struct hostent *he = gethostbyname(host);
    if (!he) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/* Parse HTTP status code from response */
static int parse_status_code(const char *response) {
    /* HTTP/1.1 200 OK */
    if (strncmp(response, "HTTP/", 5) != 0) {
        return -1;
    }
    const char *p = strchr(response, ' ');
    if (!p) return -1;
    return atoi(p + 1);
}

/* Parse Content-Type header */
static void parse_content_type(const char *response, char *content_type, size_t max_len) {
    const char *ct = strcasestr(response, "Content-Type:");
    if (!ct) {
        content_type[0] = '\0';
        return;
    }
    ct += 13; /* Skip "Content-Type:" */
    while (*ct == ' ') ct++;

    size_t i = 0;
    while (*ct && *ct != '\r' && *ct != '\n' && i < max_len - 1) {
        content_type[i++] = *ct++;
    }
    content_type[i] = '\0';
}

/* Find body start (after \r\n\r\n) */
static const char *find_body(const char *response) {
    const char *body = strstr(response, "\r\n\r\n");
    if (body) return body + 4;
    return NULL;
}

/* Fetch HTTPS URL using OpenSSL */
fetch_response_t https_fetch(const char *host, const char *path) {
    fetch_response_t resp = {0};
    resp.status_code = -1;

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();

    /* Create SSL context */
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        snprintf(resp.error, sizeof(resp.error), "SSL_CTX_new failed");
        return resp;
    }

    /* Connect TCP */
    int sock = tcp_connect(host, 443);
    if (sock < 0) {
        snprintf(resp.error, sizeof(resp.error), "TCP connect failed");
        SSL_CTX_free(ctx);
        return resp;
    }

    /* Create SSL connection */
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    /* Set SNI hostname */
    SSL_set_tlsext_host_name(ssl, host);

    /* Connect SSL */
    if (SSL_connect(ssl) <= 0) {
        snprintf(resp.error, sizeof(resp.error), "SSL_connect failed");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return resp;
    }

    /* Build HTTP request */
    char request[2048];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);

    /* Send request */
    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        snprintf(resp.error, sizeof(resp.error), "SSL_write failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return resp;
    }

    /* Read response */
    char *response = malloc(1024 * 1024); /* 1MB max */
    if (!response) {
        snprintf(resp.error, sizeof(resp.error), "malloc failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return resp;
    }

    size_t total = 0;
    int n;
    while ((n = SSL_read(ssl, response + total, BUFFER_SIZE)) > 0) {
        total += n;
        if (total >= 1024 * 1024 - BUFFER_SIZE) break; /* Limit */
    }
    response[total] = '\0';

    /* Parse response */
    resp.status_code = parse_status_code(response);
    parse_content_type(response, resp.content_type, sizeof(resp.content_type));

    const char *body = find_body(response);
    if (body) {
        resp.body_len = total - (body - response);
        resp.body = malloc(resp.body_len + 1);
        if (resp.body) {
            memcpy(resp.body, body, resp.body_len);
            resp.body[resp.body_len] = '\0';
        }
    }

    free(response);

    /* Cleanup */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return resp;
}

int main(int argc, char *argv[]) {
    const char *host = "example.com";
    const char *path = "/";

    if (argc >= 2) host = argv[1];
    if (argc >= 3) path = argv[2];

    printf("Fetching https://%s%s ...\n\n", host, path);

    fetch_response_t resp = https_fetch(host, path);

    if (resp.status_code > 0) {
        printf("Status: %d\n", resp.status_code);
        printf("Content-Type: %s\n", resp.content_type);
        printf("Body Length: %zu bytes\n", resp.body_len);
        printf("\n--- First 500 chars of body ---\n");
        if (resp.body) {
            printf("%.500s\n", resp.body);
            free(resp.body);
        }
        printf("\n--- SUCCESS ---\n");
        return 0;
    } else {
        printf("FAILED: %s\n", resp.error);
        return 1;
    }
}
