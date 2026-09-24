// dh_health.c — 见 dh_health.h。纯 C 实现, stdatomic 计数 + 互斥保护原因字符串。

#include "dh_health.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

static atomic_uint g_hook_fails     = 0;
static atomic_int  g_persist_failed = 0;
static atomic_int  g_persist_errno  = 0;
static atomic_int  g_http_failed    = 0;
static atomic_int  g_local_only     = 0;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_hook_names[256] = {0};   // 拼接没挂上的符号名
static char g_http_reason[128] = {0};
static char g_summary[512]     = {0};

__thread int dh_in_hook = 0;   // 见 dh_health.h: hook 记录路径的递归保护标志

// ============================================================
// 诊断日志(审查日志): 每板块独立行环形缓冲 + 各自落盘, 便于按模块定位问题
// ============================================================
#define DIAG_LINES    200      // 每板块保留最近 200 条
#define DIAG_LINE_LEN 240      // 单行上限
#define DIAG_FILE_CAP (256 * 1024)   // 单板块落盘文件上限, 超出轮转截断

static char g_diag[DH_DIAG_BOARD_COUNT][DIAG_LINES][DIAG_LINE_LEN];
static int  g_diag_head[DH_DIAG_BOARD_COUNT]  = {0};
static int  g_diag_count[DH_DIAG_BOARD_COUNT] = {0};
static char g_diag_out[DH_DIAG_BOARD_COUNT * DIAG_LINES * DIAG_LINE_LEN + 1024];   // dump 拼接缓冲
static char g_diag_dir[1024] = {0};
static const char *kBoardKey[DH_DIAG_BOARD_COUNT]  = { "general", "crypto", "file", "sys", "dump" };
static const char *kBoardName[DH_DIAG_BOARD_COUNT] = { "通用", "加解密", "文件", "系统", "砸壳" };

// 把某板块落盘文件的内容回填进内存环(保留最后 DIAG_LINES 行)。须在持锁时调用。
static void diag_load_board_locked(int board) {
    char path[1200];
    snprintf(path, sizeof(path), "%s/.dh_diag_%s.log", g_diag_dir, kBoardKey[board]);
    FILE *f = fopen(path, "rb");
    if (!f) return;
    char line[DIAG_LINE_LEN];
    while (fgets(line, sizeof(line), f)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
        if (!L) continue;
        strlcpy(g_diag[board][g_diag_head[board]], line, DIAG_LINE_LEN);
        g_diag_head[board] = (g_diag_head[board] + 1) % DIAG_LINES;
        if (g_diag_count[board] < DIAG_LINES) g_diag_count[board]++;
    }
    fclose(f);
}

void dh_diag_set_dir(const char *docsDir) {
    pthread_mutex_lock(&g_lock);
    if (docsDir) { strncpy(g_diag_dir, docsDir, sizeof(g_diag_dir) - 1); g_diag_dir[sizeof(g_diag_dir) - 1] = '\0'; }
    // 启动时回填落盘历史, 让重启/崩溃后面板仍能看到之前的诊断(本函数在装 hook 前调用, 读文件安全)。
    if (g_diag_dir[0]) for (int b = 0; b < DH_DIAG_BOARD_COUNT; b++) diag_load_board_locked(b);
    pthread_mutex_unlock(&g_lock);
}

// 把一行追加到板块落盘文件。dh_in_hook 包住, 避免写诊断文件本身被 file hook 记录。
static void diag_persist_line(int board, const char *line) {
    if (!g_diag_dir[0]) return;
    char path[1200];
    snprintf(path, sizeof(path), "%s/.dh_diag_%s.log", g_diag_dir, kBoardKey[board]);
    int saved = dh_in_hook; dh_in_hook = 1;
    FILE *f = fopen(path, "ab");
    if (f) {
        long sz = (fseek(f, 0, SEEK_END) == 0) ? ftell(f) : 0;
        if (sz > DIAG_FILE_CAP) {            // 超上限: 截断重开
            fclose(f);
            f = fopen(path, "wb");
            if (f) fprintf(f, "[rotated]\n");
        }
        if (f) { fprintf(f, "%s\n", line); fclose(f); }
    }
    dh_in_hook = saved;
}

void dh_diag_append(int board, const char *level, const char *msg) {
    if (board < 0 || board >= DH_DIAG_BOARD_COUNT) board = DH_DIAG_GENERAL;
    char ts[16];
    time_t now = time(NULL);
    struct tm tmv; localtime_r(&now, &tmv);
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);

    char lineCopy[DIAG_LINE_LEN];
    pthread_mutex_lock(&g_lock);
    char *slot = g_diag[board][g_diag_head[board]];
    snprintf(slot, DIAG_LINE_LEN, "[%s] %s: %s", ts, level ? level : "INFO", msg ? msg : "");
    g_diag_head[board] = (g_diag_head[board] + 1) % DIAG_LINES;
    if (g_diag_count[board] < DIAG_LINES) g_diag_count[board]++;
    strlcpy(lineCopy, slot, sizeof(lineCopy));
    pthread_mutex_unlock(&g_lock);

    diag_persist_line(board, lineCopy);   // 锁外落盘(自带 dh_in_hook 保护)
}

// 把一个板块的环形缓冲拼到 g_diag_out。须在持 g_lock 时调用。
static void dump_one_board(int board, size_t *posp) {
    size_t pos = *posp;
    int start = (g_diag_count[board] < DIAG_LINES) ? 0 : g_diag_head[board];
    for (int i = 0; i < g_diag_count[board]; i++) {
        int idx = (start + i) % DIAG_LINES;
        size_t len = strlen(g_diag[board][idx]);
        if (pos + len + 2 >= sizeof(g_diag_out)) break;
        memcpy(g_diag_out + pos, g_diag[board][idx], len);
        pos += len;
        g_diag_out[pos++] = '\n';
    }
    *posp = pos;
}

const char *dh_diag_dump(int board) {
    pthread_mutex_lock(&g_lock);
    g_diag_out[0] = '\0';
    size_t pos = 0;
    if (board >= 0 && board < DH_DIAG_BOARD_COUNT) {
        dump_one_board(board, &pos);
    } else {
        for (int b = 0; b < DH_DIAG_BOARD_COUNT; b++) {
            if (g_diag_count[b] == 0) continue;
            char hdr[64];
            int n = snprintf(hdr, sizeof(hdr), "==== [%s] ====\n", kBoardName[b]);
            if (pos + (size_t)n + 1 < sizeof(g_diag_out)) { memcpy(g_diag_out + pos, hdr, n); pos += n; }
            dump_one_board(b, &pos);
        }
    }
    g_diag_out[pos] = '\0';
    pthread_mutex_unlock(&g_lock);
    return g_diag_out;
}

const char *dh_health_hook_unhooked(void) {
    return g_hook_names;   // 只读; 拼接发生在 hook_fail 的锁内, 读取时是稳定字符串
}

void dh_health_hook_fail(int board, const char *sym) {
    // 去重: vm_protect 失败可能在多个 image / 多次 add-image 回调里对同一符号重复触发,
    // 计数应反映「不同失败符号数」而非触发次数。
    pthread_mutex_lock(&g_lock);
    int dup = (sym && sym[0] && strstr(g_hook_names, sym)) ? 1 : 0;
    if (!dup) {
        atomic_fetch_add(&g_hook_fails, 1);
        if (sym && sym[0]) {
            size_t len = strlen(g_hook_names);
            if (len + strlen(sym) + 2 < sizeof(g_hook_names)) {
                if (len) strlcat(g_hook_names, ",", sizeof(g_hook_names));
                strlcat(g_hook_names, sym, sizeof(g_hook_names));
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (!dup) {
        char m[160];
        snprintf(m, sizeof(m), "hook 未挂上(若该 App 未调用此 API 属正常): %s", sym ? sym : "(?)");
        fprintf(stderr, "[IOSDecryptHub] %s\n", m);
        dh_diag_append(board, "INFO", m);   // 入对应板块诊断日志, 不上顶部红字横幅
    }
}

void dh_health_persist_fail(int err) {
    atomic_store(&g_persist_failed, 1);
    atomic_store(&g_persist_errno, err);
    char m[64]; snprintf(m, sizeof(m), "日志落盘失败 errno=%d", err);
    fprintf(stderr, "[IOSDecryptHub/ERR] %s\n", m);
    dh_diag_append(DH_DIAG_GENERAL, "ERR", m);
}

void dh_health_http_fail(const char *reason) {
    atomic_store(&g_http_failed, 1);
    pthread_mutex_lock(&g_lock);
    if (reason) strlcpy(g_http_reason, reason, sizeof(g_http_reason));
    pthread_mutex_unlock(&g_lock);
    char m[160]; snprintf(m, sizeof(m), "HTTP 服务失败: %s", reason ? reason : "");
    fprintf(stderr, "[IOSDecryptHub/ERR] %s\n", m);
    dh_diag_append(DH_DIAG_GENERAL, "ERR", m);
}

void dh_health_http_ok(void) {
    atomic_store(&g_http_failed, 0);
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "HTTP 服务启动成功");
}

void dh_health_note_localonly(void) {
    atomic_store(&g_local_only, 1);
    fprintf(stderr, "[IOSDecryptHub] 未找到局域网 IP, 仅本地可访问\n");
    dh_diag_append(DH_DIAG_GENERAL, "INFO", "未找到局域网 IP, 仅本地可访问");
}

unsigned dh_health_hook_fail_count(void) { return atomic_load(&g_hook_fails); }
int      dh_health_persist_failed(void)  { return atomic_load(&g_persist_failed); }
int      dh_health_http_failed(void)     { return atomic_load(&g_http_failed); }
int      dh_health_local_only(void)      { return atomic_load(&g_local_only); }

const char *dh_health_summary(void) {
    pthread_mutex_lock(&g_lock);
    g_summary[0] = '\0';
    // 注意: hook 未挂上不再计入顶部红字横幅(对真实 App 多为常态, 见 dh_diag_*),
    // 只保留真正的运行时失效: 服务失败 / 落盘失败。
    if (atomic_load(&g_http_failed)) {
        if (g_summary[0]) strlcat(g_summary, " · ", sizeof(g_summary));
        strlcat(g_summary, "服务失败:", sizeof(g_summary));
        strlcat(g_summary, g_http_reason, sizeof(g_summary));
    }
    if (atomic_load(&g_persist_failed)) {
        if (g_summary[0]) strlcat(g_summary, " · ", sizeof(g_summary));
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "落盘失败(errno=%d)", atomic_load(&g_persist_errno));
        strlcat(g_summary, tmp, sizeof(g_summary));
    }
    pthread_mutex_unlock(&g_lock);
    return g_summary;
}
