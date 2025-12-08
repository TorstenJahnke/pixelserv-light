/*
 * test_udp_index.c - Unit test for UDP index write queue
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

#include "include/index_udp.h"

/* Test callback - just counts operations */
static _Atomic int g_insert_count = 0;
static _Atomic int g_remove_count = 0;

static int test_insert_cb(void *idx, const char *domain, int algo,
                          uint32_t cert_id, uint64_t expiry) {
    (void)idx; (void)domain; (void)algo; (void)cert_id; (void)expiry;
    atomic_fetch_add(&g_insert_count, 1);
    return 0;
}

static int test_remove_cb(void *idx, const char *domain, int algo) {
    (void)idx; (void)domain; (void)algo;
    atomic_fetch_add(&g_remove_count, 1);
    return 0;
}

int main(int argc, char **argv) {
    int test_count = 1000;
    if (argc > 1) test_count = atoi(argv[1]);

    printf("=== UDP Index Test ===\n\n");

    /* 1. Test ohne Server (sollte fehlschlagen) */
    printf("1. Client ohne Server (erwartet: Fehler)\n");
    int ret = index_udp_client_init(NULL, 0);
    if (ret == 0) {
        ret = index_udp_client_insert("test.example.com", CERT_ALG_RSA, 12345, 1234567890);
        printf("   insert() = %d (erwartet: -1 oder timeout)\n", ret);
    }
    index_udp_client_shutdown();
    printf("   OK - Client handling ohne Server funktioniert\n\n");

    /* 2. Server starten */
    printf("2. Server starten\n");
    index_udp_set_callbacks(test_insert_cb, test_remove_cb);

    index_udp_server_config_t config = {
        .port = 19848,  /* Nicht-Standard Port für Test */
        .bind_addr = "127.0.0.1",
        .index = NULL,
        .batch_size = 50,
        .batch_timeout_ms = 100,
        .queue_size = 10000
    };

    ret = index_udp_server_init(&config);
    if (ret != 0) {
        printf("   FEHLER: Server konnte nicht gestartet werden\n");
        return 1;
    }
    printf("   Server läuft auf Port %d\n\n", config.port);

    /* 3. Client verbinden */
    printf("3. Client initialisieren\n");
    ret = index_udp_client_init("127.0.0.1", 19848);
    if (ret != 0) {
        printf("   FEHLER: Client init fehlgeschlagen\n");
        index_udp_server_shutdown();
        return 1;
    }
    printf("   Client verbunden\n\n");

    /* 4. Ping Test */
    printf("4. Ping Test\n");
    int64_t latency = index_udp_client_ping(1000);
    if (latency >= 0) {
        printf("   Latenz: %ld µs\n\n", (long)latency);
    } else {
        printf("   WARNUNG: Ping fehlgeschlagen (ret=%ld)\n\n", (long)latency);
    }

    /* 5. Massen-Insert Test */
    printf("5. Massen-Insert Test (%d Domains)\n", test_count);
    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (int i = 0; i < test_count; i++) {
        char domain[64];
        snprintf(domain, sizeof(domain), "dga-%d.malware.test", i);

        int algo = i % 3;  /* RSA, ECDSA, SM2 rotierend */
        ret = index_udp_client_insert(domain, algo, i, 1735689600 + i);

        if (ret != 0 && i < 5) {
            printf("   WARNUNG: insert #%d fehlgeschlagen\n", i);
        }
    }

    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("   Gesendet: %d in %.3f s (%.0f/s)\n", test_count, elapsed, test_count/elapsed);

    /* 6. Sync und warten */
    printf("\n6. Sync (warte auf Verarbeitung)\n");
    usleep(200000);  /* 200ms warten für Batching */
    index_udp_client_sync(1000);
    usleep(100000);  /* Noch 100ms für letzten Batch */

    /* 7. Statistiken */
    printf("\n7. Server-Statistiken\n");
    index_udp_stats_t stats;
    index_udp_server_stats(&stats);
    printf("   Inserts verarbeitet: %lu\n", (unsigned long)stats.inserts);
    printf("   Removes verarbeitet: %lu\n", (unsigned long)stats.removes);
    printf("   Queue Drops: %lu\n", (unsigned long)stats.queue_drops);
    printf("   Callback-Zähler: inserts=%d, removes=%d\n",
           atomic_load(&g_insert_count), atomic_load(&g_remove_count));

    /* 8. Aufräumen */
    printf("\n8. Cleanup\n");
    index_udp_client_shutdown();
    index_udp_server_shutdown();
    printf("   Fertig\n\n");

    /* Ergebnis */
    int processed = atomic_load(&g_insert_count);
    printf("=== ERGEBNIS ===\n");
    if (processed >= test_count * 0.95) {  /* 95% Erfolgsrate */
        printf("BESTANDEN: %d/%d Inserts verarbeitet (%.1f%%)\n",
               processed, test_count, 100.0 * processed / test_count);
        return 0;
    } else {
        printf("FEHLGESCHLAGEN: Nur %d/%d Inserts verarbeitet (%.1f%%)\n",
               processed, test_count, 100.0 * processed / test_count);
        return 1;
    }
}
