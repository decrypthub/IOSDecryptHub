// dh_capture.c — 见 dh_capture.h。纯 C 实现, atomic 读 + 互斥存盘。

#include "dh_capture.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

static atomic_int g_sub[DH_CAP_SUB_COUNT];        // 1=捕获, 0=关闭
static atomic_int g_cat_paused[DH_CAP_CAT_COUNT]; // 1=暂停

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_conf_path[1024] = {0};

static const char *kSubNames[DH_CAP_SUB_COUNT] = {
    "DIGEST", "HMAC", "SYMMETRIC", "ASYMMETRIC", "KDF",
    "FILE_OPEN", "FILE_WRITE", "FILE_READ", "FILE_MMAP", "FILE_UNLINK", "FILE_RENAME",
    "SYS_DLOPEN",
    "SYS_DLSYM",
    "EVP",
    "KEYCHAIN",
    "ENV_PROBE",
    "NETWORK",
};

static void set_defaults(void) {
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++) atomic_store(&g_sub[i], 1);
    for (int i = 0; i < DH_CAP_CAT_COUNT; i++) atomic_store(&g_cat_paused[i], 0);
}

// v2 格式(按名/索引, 每行一项): 首行 "v2", 后跟 "sub <NAME> <0/1>" 与 "cat <index> <0/1>"。
// 好处: 新增子类/分类时, 旧配置里已有的项按名匹配照常生效, 缺失项保默认、未知项忽略 —— 升级不丢配置。
// 须在持锁状态调用。
static void save_locked(void) {
    if (!g_conf_path[0]) return;
    FILE *f = fopen(g_conf_path, "wb");
    if (!f) return;
    fprintf(f, "v2\n");
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        fprintf(f, "sub %s %d\n", dh_capture_sub_name((dh_cap_sub)i), atomic_load(&g_sub[i]));
    for (int i = 0; i < DH_CAP_CAT_COUNT; i++)
        fprintf(f, "cat %d %d\n", i, atomic_load(&g_cat_paused[i]));
    fclose(f);
}

void dh_capture_load(const char *confPath) {
    pthread_mutex_lock(&g_lock);
    set_defaults();
    if (confPath) {
        strncpy(g_conf_path, confPath, sizeof(g_conf_path) - 1);
        g_conf_path[sizeof(g_conf_path) - 1] = '\0';
    }
    if (g_conf_path[0]) {
        FILE *f = fopen(g_conf_path, "rb");
        if (f) {
            char line[160];
            if (fgets(line, sizeof(line), f) && strncmp(line, "v2", 2) == 0) {
                // v2: 按名/索引解析, 已有项覆盖默认, 缺失/未知不影响
                char name[80]; int idx, val;
                while (fgets(line, sizeof(line), f)) {
                    if (sscanf(line, "sub %79s %d", name, &val) == 2) {
                        for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
                            if (strcmp(name, dh_capture_sub_name((dh_cap_sub)i)) == 0) { atomic_store(&g_sub[i], val ? 1 : 0); break; }
                    } else if (sscanf(line, "cat %d %d", &idx, &val) == 2) {
                        if (idx >= 0 && idx < DH_CAP_CAT_COUNT) atomic_store(&g_cat_paused[idx], val ? 1 : 0);
                    }
                }
            } else {
                // 旧位置格式(v1): 回到文件头, 仅当项数完全匹配才采用(fail-safe), 否则保持默认。
                fseek(f, 0, SEEK_SET);
                const int total = DH_CAP_SUB_COUNT + DH_CAP_CAT_COUNT;
                int vals[DH_CAP_SUB_COUNT + DH_CAP_CAT_COUNT];
                int n = 0, v;
                while (n < total && fscanf(f, "%d", &v) == 1) vals[n++] = v;
                if (n == total) {
                    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)  atomic_store(&g_sub[i], vals[i] ? 1 : 0);
                    for (int i = 0; i < DH_CAP_CAT_COUNT; i++)  atomic_store(&g_cat_paused[i], vals[DH_CAP_SUB_COUNT + i] ? 1 : 0);
                }
            }
            fclose(f);
        }
    }
    pthread_mutex_unlock(&g_lock);
}

int dh_capture_sub_enabled(dh_cap_sub sub) {
    if (sub < 0 || sub >= DH_CAP_SUB_COUNT) return 1;
    return atomic_load(&g_sub[sub]);
}

void dh_capture_set_sub(dh_cap_sub sub, int on) {
    if (sub < 0 || sub >= DH_CAP_SUB_COUNT) return;
    atomic_store(&g_sub[sub], on ? 1 : 0);
    pthread_mutex_lock(&g_lock); save_locked(); pthread_mutex_unlock(&g_lock);
}

const char *dh_capture_sub_name(dh_cap_sub sub) {
    if (sub < 0 || sub >= DH_CAP_SUB_COUNT) return "";
    return kSubNames[sub];
}

int dh_capture_cat_paused(int cat) {
    if (cat < 0 || cat >= DH_CAP_CAT_COUNT) return 0;
    return atomic_load(&g_cat_paused[cat]);
}

void dh_capture_set_cat_paused(int cat, int paused) {
    if (cat < 0 || cat >= DH_CAP_CAT_COUNT) return;
    atomic_store(&g_cat_paused[cat], paused ? 1 : 0);
    pthread_mutex_lock(&g_lock); save_locked(); pthread_mutex_unlock(&g_lock);
}
