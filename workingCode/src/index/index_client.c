/*
 * index_client.c - Index Client for Worker Processes
 *
 * Connects to the index master server to perform lookups and inserts.
 * Thread-safe: uses mutex to protect socket access.
 */

#include "index/index_client.h"
#include "index/index_protocol.h"
#include "core/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

/* Client state */
static int g_socket_fd = -1;
static char g_socket_path[108] = "";  /* Match sun_path size */
static pthread_mutex_t g_client_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_connected = 0;

/* Connect to master */
static int connect_to_master(void) {
    if (g_socket_fd >= 0) {
        close(g_socket_fd);
    }

    g_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_socket_fd < 0) {
        perror("[INDEX-CLIENT] socket failed");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_socket_path);

    if (connect(g_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[INDEX-CLIENT] connect failed");
        close(g_socket_fd);
        g_socket_fd = -1;
        return -1;
    }

    g_connected = 1;
    return 0;
}

/* Send command and receive response */
static int send_recv(const char *cmd, char *response, int response_len) {
    /* Send command */
    int cmd_len = strlen(cmd);
    if (write(g_socket_fd, cmd, cmd_len) != cmd_len) {
        g_connected = 0;
        return -1;
    }

    /* Read response (single line) */
    int total = 0;
    while (total < response_len - 1) {
        ssize_t n = read(g_socket_fd, response + total, 1);
        if (n <= 0) {
            g_connected = 0;
            return -1;
        }
        if (response[total] == '\n') {
            response[total] = '\0';
            return 0;
        }
        total++;
    }

    response[total] = '\0';
    return 0;
}

/* Initialize client connection */
int index_client_init(const char *socket_path) {
    pthread_mutex_lock(&g_client_mutex);

    strncpy(g_socket_path, socket_path, sizeof(g_socket_path) - 1);

    int ret = connect_to_master();
    if (ret == 0) {
        log_msg(LGG_INFO, "[INDEX-CLIENT] Connected to master at %s", socket_path);
    }

    pthread_mutex_unlock(&g_client_mutex);
    return ret;
}

/* Close client connection */
void index_client_close(void) {
    pthread_mutex_lock(&g_client_mutex);

    if (g_socket_fd >= 0) {
        close(g_socket_fd);
        g_socket_fd = -1;
    }
    g_connected = 0;

    pthread_mutex_unlock(&g_client_mutex);
}

/* Ensure connected (reconnect if needed) */
static int ensure_connected(void) {
    if (!g_connected || g_socket_fd < 0) {
        return connect_to_master();
    }
    return 0;
}

/* Lookup certificate in master index */
int index_client_lookup(const char *domain, uint8_t *shard_id,
                        uint32_t *cert_id, uint64_t *expiry) {
    if (!domain) return -1;

    pthread_mutex_lock(&g_client_mutex);

    /* Ensure connected */
    if (ensure_connected() < 0) {
        pthread_mutex_unlock(&g_client_mutex);
        return -1;
    }

    /* Send LOOKUP command */
    char cmd[IDX_MSG_MAXLEN];
    snprintf(cmd, sizeof(cmd), "%s %s\n", IDX_CMD_LOOKUP, domain);

    char response[IDX_MSG_MAXLEN];
    if (send_recv(cmd, response, sizeof(response)) < 0) {
        /* Try reconnect once */
        if (connect_to_master() < 0 || send_recv(cmd, response, sizeof(response)) < 0) {
            pthread_mutex_unlock(&g_client_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&g_client_mutex);

    /* Parse response */
    if (strncmp(response, IDX_RSP_FOUND, strlen(IDX_RSP_FOUND)) == 0) {
        unsigned int s, c;
        unsigned long e;
        if (sscanf(response + strlen(IDX_RSP_FOUND), " %u %u %lu", &s, &c, &e) == 3) {
            if (shard_id) *shard_id = (uint8_t)s;
            if (cert_id) *cert_id = (uint32_t)c;
            if (expiry) *expiry = (uint64_t)e;
            return 0;  /* Found */
        }
    }

    return -1;  /* Not found or error */
}

/* Insert certificate into master index */
int index_client_insert(const char *domain, uint8_t shard_id,
                        uint32_t cert_id, uint64_t expiry) {
    if (!domain) return -1;

    pthread_mutex_lock(&g_client_mutex);

    /* Ensure connected */
    if (ensure_connected() < 0) {
        pthread_mutex_unlock(&g_client_mutex);
        return -1;
    }

    /* Send INSERT command */
    char cmd[IDX_MSG_MAXLEN];
    snprintf(cmd, sizeof(cmd), "%s %s %u %u %lu\n",
             IDX_CMD_INSERT, domain, shard_id, cert_id, expiry);

    char response[IDX_MSG_MAXLEN];
    if (send_recv(cmd, response, sizeof(response)) < 0) {
        /* Try reconnect once */
        if (connect_to_master() < 0 || send_recv(cmd, response, sizeof(response)) < 0) {
            pthread_mutex_unlock(&g_client_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&g_client_mutex);

    /* Check response */
    if (strncmp(response, IDX_RSP_OK, strlen(IDX_RSP_OK)) == 0) {
        return 0;
    }

    return -1;
}

/* Ping master to check connection */
int index_client_ping(void) {
    pthread_mutex_lock(&g_client_mutex);

    if (ensure_connected() < 0) {
        pthread_mutex_unlock(&g_client_mutex);
        return -1;
    }

    char cmd[32];
    snprintf(cmd, sizeof(cmd), "%s\n", IDX_CMD_PING);

    char response[IDX_MSG_MAXLEN];
    int ret = send_recv(cmd, response, sizeof(response));

    pthread_mutex_unlock(&g_client_mutex);

    if (ret == 0 && strncmp(response, IDX_RSP_PONG, strlen(IDX_RSP_PONG)) == 0) {
        return 0;
    }

    return -1;
}

/* Request index rescan */
int index_client_scan(size_t *count) {
    pthread_mutex_lock(&g_client_mutex);

    if (ensure_connected() < 0) {
        pthread_mutex_unlock(&g_client_mutex);
        return -1;
    }

    char cmd[32];
    snprintf(cmd, sizeof(cmd), "%s\n", IDX_CMD_SCAN);

    char response[IDX_MSG_MAXLEN];
    if (send_recv(cmd, response, sizeof(response)) < 0) {
        pthread_mutex_unlock(&g_client_mutex);
        return -1;
    }

    pthread_mutex_unlock(&g_client_mutex);

    if (strncmp(response, IDX_RSP_OK, strlen(IDX_RSP_OK)) == 0) {
        if (count) {
            size_t c = 0;
            sscanf(response + strlen(IDX_RSP_OK), " %zu", &c);
            *count = c;
        }
        return 0;
    }

    return -1;
}

/* Check if client is connected */
int index_client_is_connected(void) {
    return g_connected && g_socket_fd >= 0;
}
