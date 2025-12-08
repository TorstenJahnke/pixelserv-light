/*
 * index_master.c - Index Master Server
 *
 * Maintains the certificate index and serves lookup/insert requests
 * from worker processes via Unix socket.
 */

#include "index/index_master.h"
#include "index/index_protocol.h"
#include "certs/cert_index.h"
#include "core/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/stat.h>

#define MAX_EVENTS 64
#define MAX_CLIENTS 128

/* Global state */
static int g_server_fd = -1;
static int g_epoll_fd = -1;
static cert_index_t *g_index = NULL;
static char g_pem_dir[256] = "";
static atomic_bool g_shutdown = false;

/* Client connection state */
typedef struct {
    int fd;
    char buf[IDX_MSG_MAXLEN];
    int buf_len;
} client_t;

static client_t g_clients[MAX_CLIENTS];
static int g_num_clients = 0;

/* Statistics */
static atomic_long g_lookups = 0;
static atomic_long g_inserts = 0;
static atomic_long g_hits = 0;
static atomic_long g_misses = 0;

/* Set socket non-blocking */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Send response to client */
static int send_response(int fd, const char *fmt, ...) {
    char buf[IDX_MSG_MAXLEN];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len > 0) {
        return write(fd, buf, len);
    }
    return -1;
}

/* Handle LOOKUP command */
static void handle_lookup(int fd, const char *domain) {
    atomic_fetch_add(&g_lookups, 1);

    cert_index_result_t result;
    memset(&result, 0, sizeof(result));

    if (cert_index_lookup(g_index, domain, &result) == CERT_INDEX_OK && result.found) {
        atomic_fetch_add(&g_hits, 1);
        send_response(fd, "%s %u %u %lu\n", IDX_RSP_FOUND,
                      result.shard_id, result.cert_id, (unsigned long)result.expiry);
    } else {
        atomic_fetch_add(&g_misses, 1);
        send_response(fd, "%s\n", IDX_RSP_NOTFOUND);
    }
}

/* Handle INSERT command */
static void handle_insert(int fd, const char *domain, uint8_t shard_id,
                          uint32_t cert_id, uint64_t expiry) {
    atomic_fetch_add(&g_inserts, 1);

    if (cert_index_insert(g_index, domain, shard_id, cert_id, expiry) == 0) {
        send_response(fd, "%s\n", IDX_RSP_OK);
    } else {
        send_response(fd, "%s insert failed\n", IDX_RSP_ERROR);
    }
}

/* Handle REMOVE command */
static void handle_remove(int fd, const char *domain) {
    if (cert_index_delete(g_index, domain) == CERT_INDEX_OK) {
        send_response(fd, "%s\n", IDX_RSP_OK);
    } else {
        send_response(fd, "%s\n", IDX_RSP_NOTFOUND);
    }
}

/* Handle STATS command */
static void handle_stats(int fd) {
    size_t count = 0, capacity = 0;
    cert_index_get_stats(g_index, &count, &capacity);
    send_response(fd, "%s %zu lookups=%ld hits=%ld misses=%ld inserts=%ld\n",
                  IDX_RSP_STATS, count,
                  atomic_load(&g_lookups),
                  atomic_load(&g_hits),
                  atomic_load(&g_misses),
                  atomic_load(&g_inserts));
}

/* Handle SCAN command (rebuild from disk) */
static void handle_scan(int fd) {
    log_msg(LGG_INFO, "[INDEX-MASTER] Scanning %s for certificates...", g_pem_dir);

    /* Rebuild index from existing certificates */
    if (g_index && cert_index_rebuild(g_index) == CERT_INDEX_OK) {
        size_t count = 0, capacity = 0;
        cert_index_get_stats(g_index, &count, &capacity);
        log_msg(LGG_INFO, "[INDEX-MASTER] Scan complete: %zu certificates", count);
        send_response(fd, "%s %zu\n", IDX_RSP_OK, count);
    } else {
        send_response(fd, "%s scan failed\n", IDX_RSP_ERROR);
    }
}

/* Handle PING command */
static void handle_ping(int fd) {
    send_response(fd, "%s\n", IDX_RSP_PONG);
}

/* Parse and handle a command */
static void handle_command(int fd, char *cmd) {
    char *token = strtok(cmd, " \t\n");
    if (!token) return;

    if (strcmp(token, IDX_CMD_LOOKUP) == 0) {
        char *domain = strtok(NULL, " \t\n");
        if (domain) {
            handle_lookup(fd, domain);
        } else {
            send_response(fd, "%s missing domain\n", IDX_RSP_ERROR);
        }
    }
    else if (strcmp(token, IDX_CMD_INSERT) == 0) {
        char *domain = strtok(NULL, " \t\n");
        char *shard_str = strtok(NULL, " \t\n");
        char *cert_str = strtok(NULL, " \t\n");
        char *expiry_str = strtok(NULL, " \t\n");

        if (domain && shard_str && cert_str && expiry_str) {
            uint8_t shard_id = (uint8_t)atoi(shard_str);
            uint32_t cert_id = (uint32_t)atoi(cert_str);
            uint64_t expiry = (uint64_t)strtoull(expiry_str, NULL, 10);
            handle_insert(fd, domain, shard_id, cert_id, expiry);
        } else {
            send_response(fd, "%s missing parameters\n", IDX_RSP_ERROR);
        }
    }
    else if (strcmp(token, IDX_CMD_REMOVE) == 0) {
        char *domain = strtok(NULL, " \t\n");
        if (domain) {
            handle_remove(fd, domain);
        } else {
            send_response(fd, "%s missing domain\n", IDX_RSP_ERROR);
        }
    }
    else if (strcmp(token, IDX_CMD_STATS) == 0) {
        handle_stats(fd);
    }
    else if (strcmp(token, IDX_CMD_SCAN) == 0) {
        handle_scan(fd);
    }
    else if (strcmp(token, IDX_CMD_PING) == 0) {
        handle_ping(fd);
    }
    else {
        send_response(fd, "%s unknown command\n", IDX_RSP_ERROR);
    }
}

/* Handle data from client */
static void handle_client_data(client_t *client) {
    char buf[IDX_MSG_MAXLEN];
    ssize_t n = read(client->fd, buf, sizeof(buf) - 1);

    if (n <= 0) {
        /* Client disconnected or error */
        return;
    }

    buf[n] = '\0';

    /* Append to client buffer */
    int space = sizeof(client->buf) - client->buf_len - 1;
    if (n > space) n = space;
    memcpy(client->buf + client->buf_len, buf, n);
    client->buf_len += n;
    client->buf[client->buf_len] = '\0';

    /* Process complete lines */
    char *line_start = client->buf;
    char *newline;

    while ((newline = strchr(line_start, '\n')) != NULL) {
        *newline = '\0';
        handle_command(client->fd, line_start);
        line_start = newline + 1;
    }

    /* Move remaining data to start of buffer */
    int remaining = client->buf_len - (line_start - client->buf);
    if (remaining > 0 && line_start != client->buf) {
        memmove(client->buf, line_start, remaining);
    }
    client->buf_len = remaining;
}

/* Find client by fd */
static client_t* find_client(int fd) {
    for (int i = 0; i < g_num_clients; i++) {
        if (g_clients[i].fd == fd) {
            return &g_clients[i];
        }
    }
    return NULL;
}

/* Remove client */
static void remove_client(int fd) {
    for (int i = 0; i < g_num_clients; i++) {
        if (g_clients[i].fd == fd) {
            close(fd);
            /* Move last client to this slot */
            if (i < g_num_clients - 1) {
                g_clients[i] = g_clients[g_num_clients - 1];
            }
            g_num_clients--;
            return;
        }
    }
}

/* Accept new client connection */
static void accept_client(void) {
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(g_server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("[INDEX-MASTER] accept failed");
        }
        return;
    }

    if (g_num_clients >= MAX_CLIENTS) {
        log_msg(LGG_WARNING, "[INDEX-MASTER] Too many clients, rejecting");
        close(client_fd);
        return;
    }

    set_nonblocking(client_fd);

    /* Add to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("[INDEX-MASTER] epoll_ctl ADD failed");
        close(client_fd);
        return;
    }

    /* Add to client list */
    g_clients[g_num_clients].fd = client_fd;
    g_clients[g_num_clients].buf_len = 0;
    g_num_clients++;

    log_msg(LGG_DEBUG, "[INDEX-MASTER] Client connected (total: %d)", g_num_clients);
}

/* Signal handler */
static void signal_handler(int sig) {
    (void)sig;
    atomic_store(&g_shutdown, true);
}

/* Initialize index master */
int index_master_init(const char *socket_path, const char *pem_dir) {
    /* Save pem_dir */
    strncpy(g_pem_dir, pem_dir, sizeof(g_pem_dir) - 1);

    /* Create index with configuration */
    cert_index_config_t idx_cfg = {
        .base_dir = pem_dir,
        .ca_name = "RSA",
        .max_certs = 2000000,  /* 2M certificates */
        .create_dirs = true
    };

    g_index = cert_index_create(&idx_cfg);
    if (!g_index) {
        log_msg(LGG_ERR, "[INDEX-MASTER] Failed to create index");
        return -1;
    }

    /* Rebuild index from existing certificates */
    log_msg(LGG_INFO, "[INDEX-MASTER] Scanning %s for existing certificates...", pem_dir);
    cert_index_rebuild(g_index);
    size_t count = 0, capacity = 0;
    cert_index_get_stats(g_index, &count, &capacity);
    log_msg(LGG_INFO, "[INDEX-MASTER] Loaded %zu certificates", count);

    /* Remove old socket file */
    unlink(socket_path);

    /* Create Unix socket */
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        perror("[INDEX-MASTER] socket failed");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[INDEX-MASTER] bind failed");
        close(g_server_fd);
        return -1;
    }

    /* Allow all users to connect */
    chmod(socket_path, 0777);

    if (listen(g_server_fd, 32) < 0) {
        perror("[INDEX-MASTER] listen failed");
        close(g_server_fd);
        return -1;
    }

    set_nonblocking(g_server_fd);

    /* Create epoll */
    g_epoll_fd = epoll_create1(0);
    if (g_epoll_fd < 0) {
        perror("[INDEX-MASTER] epoll_create1 failed");
        close(g_server_fd);
        return -1;
    }

    /* Add server socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = g_server_fd;

    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_server_fd, &ev) < 0) {
        perror("[INDEX-MASTER] epoll_ctl failed");
        close(g_server_fd);
        close(g_epoll_fd);
        return -1;
    }

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    log_msg(LGG_INFO, "[INDEX-MASTER] Listening on %s", socket_path);

    return 0;
}

/* Run the index master event loop */
void index_master_run(void) {
    struct epoll_event events[MAX_EVENTS];

    log_msg(LGG_INFO, "[INDEX-MASTER] Starting event loop...");

    while (!atomic_load(&g_shutdown)) {
        int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 1000);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("[INDEX-MASTER] epoll_wait failed");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == g_server_fd) {
                /* New connection */
                accept_client();
            } else {
                /* Client data or disconnect */
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    log_msg(LGG_DEBUG, "[INDEX-MASTER] Client disconnected");
                    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                    remove_client(fd);
                } else if (events[i].events & EPOLLIN) {
                    client_t *client = find_client(fd);
                    if (client) {
                        handle_client_data(client);
                    }
                }
            }
        }
    }

    log_msg(LGG_INFO, "[INDEX-MASTER] Shutting down...");
}

/* Cleanup */
void index_master_shutdown(void) {
    /* Close all clients */
    for (int i = 0; i < g_num_clients; i++) {
        close(g_clients[i].fd);
    }
    g_num_clients = 0;

    if (g_epoll_fd >= 0) {
        close(g_epoll_fd);
        g_epoll_fd = -1;
    }

    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }

    if (g_index) {
        cert_index_destroy(g_index);
        g_index = NULL;
    }

    log_msg(LGG_INFO, "[INDEX-MASTER] Shutdown complete");
}

/* Get statistics */
void index_master_get_stats(long *lookups, long *hits, long *misses, long *inserts) {
    if (lookups) *lookups = atomic_load(&g_lookups);
    if (hits) *hits = atomic_load(&g_hits);
    if (misses) *misses = atomic_load(&g_misses);
    if (inserts) *inserts = atomic_load(&g_inserts);
}
