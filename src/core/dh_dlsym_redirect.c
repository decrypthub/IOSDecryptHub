// dh_dlsym_redirect.c — 见 dh_dlsym_redirect.h

#include "dh_dlsym_redirect.h"
#include <string.h>

#define DH_DLSYM_MAX 160

static struct {
    const char *name;
    void       *fn;
} g_table[DH_DLSYM_MAX];

static size_t g_count;

void dh_dlsym_register_rebindings(const struct rebinding *r, size_t n) {
    if (!r) return;
    for (size_t i = 0; i < n; i++) {
        if (!r[i].name || !r[i].replacement) continue;
        for (size_t j = 0; j < g_count; j++) {
            if (strcmp(g_table[j].name, r[i].name) == 0) {
                g_table[j].fn = r[i].replacement;
                goto next;
            }
        }
        if (g_count >= DH_DLSYM_MAX) break;
        g_table[g_count].name = r[i].name;
        g_table[g_count].fn   = r[i].replacement;
        g_count++;
    next:;
    }
}

void *dh_dlsym_redirect_lookup(const char *symbol) {
    if (!symbol || !*symbol) return NULL;
    for (size_t i = 0; i < g_count; i++) {
        if (strcmp(g_table[i].name, symbol) == 0)
            return g_table[i].fn;
    }
    return NULL;
}
