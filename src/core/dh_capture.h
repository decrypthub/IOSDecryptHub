// dh_capture.h — 捕获配置中心 (纯 C, 零依赖)
//
// 统一持有「捕获哪些子类型」与「每类暂停」开关, 并持久化到沙箱(Documents/.dh_capture.conf),
// 重启/重新注入后仍生效。各 hook 在记录前查 dh_capture_sub_enabled() 决定是否记录(源头早退,
// 省掉构造 entry / 算调用栈的开销)。线程安全: 读用 atomic, 存盘用互斥。

#ifndef DH_CAPTURE_H
#define DH_CAPTURE_H

#ifdef __cplusplus
extern "C" {
#endif

// 捕获子类型 —— 扁平索引, 顺序固定(持久化文件按此顺序写 0/1, 不可随意调整)。
typedef enum {
    DH_CAP_DIGEST = 0,     // 摘要族 (MD*/SHA*)
    DH_CAP_HMAC,           // HMAC-*
    DH_CAP_SYMMETRIC,      // AES/DES/3DES/RC4/...
    DH_CAP_ASYMMETRIC,     // RSA/EC sign/verify/enc/dec
    DH_CAP_KDF,            // PBKDF2
    DH_CAP_FILE_OPEN,
    DH_CAP_FILE_WRITE,
    DH_CAP_FILE_READ,      // read/pread —— 命中已跟踪 fd 时 dump 读出内容
    DH_CAP_FILE_MMAP,      // mmap —— 映射已跟踪 fd 时记路径/长度/offset
    DH_CAP_FILE_UNLINK,
    DH_CAP_FILE_RENAME,
    DH_CAP_SYS_DLOPEN,
    DH_CAP_SYS_DLSYM,      // dlsym 动态符号解析(含重定向到 hook wrapper)
    DH_CAP_EVP,            // OpenSSL EVP 对称加解密 (Init/Update/Final/ctrl)
    DH_CAP_KEYCHAIN,       // SecItem* Keychain 查询/增改删 (token/密码存取)
    DH_CAP_ENV_PROBE,      // 环境探测观测 (sysctl/uname/getenv/ptrace/csops/stat/access)
    DH_CAP_NETWORK,        // 网络: NSURLSession 请求 + SSL_write/read 明文
    DH_CAP_SUB_COUNT
} dh_cap_sub;

#define DH_CAP_CAT_COUNT 9   // = DHCategoryOther + 1 (含 Network / Keychain)

// 从沙箱加载持久化配置(应在安装 hook 之前调用)。confPath = .dh_capture.conf 绝对路径;
// 文件不存在或格式不符则用「全部开启 / 不暂停」的默认值。
void dh_capture_load(const char *confPath);

// 子类型是否启用捕获(默认全开)。高频路径调用, atomic 无锁。越界返回 1(放行)。
int  dh_capture_sub_enabled(dh_cap_sub sub);
void dh_capture_set_sub(dh_cap_sub sub, int on);   // 设置并立即存盘
const char *dh_capture_sub_name(dh_cap_sub sub);   // 给 /api/capture 的开关名(越界返回 "")

// 每类暂停(cat = DHCategory 值, 0..7)。
int  dh_capture_cat_paused(int cat);
void dh_capture_set_cat_paused(int cat, int paused);  // 设置并立即存盘

#ifdef __cplusplus
}
#endif

#endif // DH_CAPTURE_H
