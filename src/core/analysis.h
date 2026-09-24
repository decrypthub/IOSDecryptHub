// analysis.h — 二进制分析模块 (capstone 反汇编 + 进程内存读取 + Mach-O 镜像枚举)
//
// 对 capstone 与项目现有的 macho_dump 能力做统一包装, 供 MCP 工具调用。
// 符号表枚举不在这里 —— MCP 层直接用 dh_symtab (与 /api/symbols 同一条路径)。

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// 反汇编
// ============================================================

// 结构化操作数。保留常用寄存器/立即数/内存字段，避免 MCP 调用方重新解析 op_str。
// 固定上限保证注入进程内的内存占用可预测；ARM64 当前最多 8 个操作数。
#define ANALYSIS_MAX_OPERANDS 8

typedef enum {
    AnalysisOperandInvalid = 0,
    AnalysisOperandRegister,
    AnalysisOperandImmediate,
    AnalysisOperandMemory,
    AnalysisOperandFloatingPoint,
    AnalysisOperandOther,
} AnalysisOperandType;

typedef struct {
    uint8_t  type;              // AnalysisOperandType
    uint8_t  access;            // bit 0=read, bit 1=write
    uint16_t raw_type;          // Capstone 原始 operand type，供 unknown/other 排查
    int64_t  immediate;
    double   fp;
    int64_t  displacement;
    char     reg[16];
    char     base[16];
    char     index[16];
    char     shift[8];
    uint8_t  shift_value;
    char     extender[8];
} AnalysisOperand;

// 单条反汇编指令
typedef struct {
    uint64_t address;          // 指令地址
    uint32_t id;               // Capstone instruction id
    char     mnemonic[32];     // 助记符 (如 "stp", "mov")
    char     op_str[192];      // 操作数字符串
    uint8_t  bytes[16];        // 原始机器码
    uint8_t  size;             // 指令长度 (字节)
    uint8_t  operand_count;
    uint8_t  operands_truncated;
    uint8_t  is_jump;
    uint8_t  is_call;
    uint8_t  is_return;
    uint8_t  writes_flags;
    uint8_t  writeback;
    AnalysisOperand operands[ANALYSIS_MAX_OPERANDS];
} AnalysisInsn;

// 反汇编一段字节缓冲。
//   arch: "arm64"/"aarch64" | "arm" | "thumb"; NULL 默认 arm64。
// 返回反汇编出的指令数, 或 -1 表示 capstone 初始化/参数错误。
int analysis_disassemble(const uint8_t *code, size_t size, uint64_t address,
                         const char *arch, AnalysisInsn *out, int max_count);

// 安全读取本进程内存 address 处的 size 字节并反汇编。
// 用 vm_read_overwrite: 地址不可读时返回 -2 (而非崩溃), 参数/反汇编错误返回 -1。
// size 会被截断到 64KB 上限。
int analysis_disassemble_at(uint64_t address, size_t size, const char *arch,
                            AnalysisInsn *out, int max_count);

// 从 address 反汇编, 遇到 ret 即停 (函数边界启发式), 或达到 max_bytes/max_count。
// 内存不可读返回 -2, 参数/反汇编错误返回 -1, 否则返回指令数。max_bytes 截断到 64KB。
int analysis_disassemble_func(uint64_t address, size_t max_bytes, const char *arch,
                              AnalysisInsn *out, int max_count);

// ============================================================
// 符号 / 内存
// ============================================================

// 地址归属结果。优先以 LC_FUNCTION_STARTS 确定包含函数，只有缺少函数元数据时才
// 退回 dladdr 的“最近符号”。symbol_source/confidence 让调用方区分精确符号、
// synthetic sub_<runtime> 与低可信 nearest dladdr，避免把超大偏移误当函数名。
typedef struct {
    uint64_t normalized_address;
    uint64_t function_start;
    uint64_t function_end;
    uint64_t function_vmaddr;
    uint64_t function_offset;
    uint64_t symbol_offset;
    char     image[256];
    char     symbol[512];
    char     symbol_source[32];   // "dladdr_exact" | "lc_function_starts" | "dladdr_nearest" | "image"
    char     confidence[16];      // "high" | "low" | "none"
    int      address_mapped;
    int      has_function;
    int      has_symbol;          // 真实符号名；synthetic sub_ 为 0
} AnalysisAddressInfo;

// 解析运行时地址的镜像、包含函数与可信符号。PAC 地址会先规范化。
// 找到镜像或 dladdr 归属返回 0，完全无法归属返回 -1。
int analysis_address_info(uint64_t addr, AnalysisAddressInfo *out);

// 解析符号名到运行时地址 (dlsym RTLD_DEFAULT)。
// 找到返回 0 并填 *out_addr 与 out_image(所属镜像短名); 未找到返回 -1。
int analysis_resolve_symbol(const char *name, uint64_t *out_addr,
                            char *out_image, size_t image_len);

// 地址 -> 可信函数标签 + 偏移。优先 LC_FUNCTION_STARTS 确定包含函数，再接受入口处
// 的精确 dladdr 符号；strip 镜像返回 synthetic sub_<runtime>。完全无法归属返回 -1。
// out_sym 已去前导下划线。
int analysis_symbolicate(uint64_t addr, char *out_sym, size_t sym_len,
                         uint64_t *out_offset, char *out_image, size_t image_len,
                         uint64_t *out_normalized);

// 安全读内存到 out_buf。返回实际读到的字节数, -2 不可读, -1 参数错误。
// size 截断到 min(buf_cap, 64KB)。
int analysis_read_memory(uint64_t addr, size_t size, uint8_t *out_buf, size_t buf_cap);

// 在 [addr, addr+length) 内搜索 pattern (plen 字节, 分块读, 跳过不可读页, 处理块边界)。
// 命中地址写入 out_hits(至多 max_hits), 返回命中数; length 截断到 256MB。
int analysis_search_memory(uint64_t addr, size_t length,
                           const uint8_t *pattern, size_t plen,
                           uint64_t *out_hits, int max_hits);

// ============================================================
// Mach-O 镜像 (复用 macho_dump)
// ============================================================

typedef struct {
    char     name[256];        // 镜像短名
    char     kind[16];         // "main" / "framework"
    uint64_t load_address;     // 内存中的 Mach-O 头地址 (= 加载基址, 可直接喂给 disassemble_at)
    int      encrypted;        // cryptid != 0
    uint32_t cryptid;
    uint64_t cryptsize;        // 加密段大小 (字节); 未加密镜像为 0
} AnalysisMachoImage;

// 枚举主 App bundle 内已加载的 64 位镜像 (主程序 + 内嵌 Frameworks/.dylib)。
// 返回镜像数, 或 -1 表示参数错误。
int analysis_list_macho_images(AnalysisMachoImage *out, int max_count);

// 完整 dyld 镜像地图。与 list_images 的 fishhook/import 索引语义不同，这里不会因
// imports==0 过滤镜像，供地址归属、插件检测和扫描目标选择使用。
typedef struct {
    int      dyld_index;
    int      is_main;
    char     scope[16];        // "app" | "system" | "external"
    char     name[256];
    char     path[1024];
    char     uuid[37];
    uint64_t load_address;
    int64_t  slide;
    uint64_t text_start;
    uint64_t text_end;
    uint32_t filetype;
    uint32_t cryptid;
    uint64_t cryptsize;
} AnalysisLoadedImage;

int analysis_list_loaded_images(const char *query, int include_system,
                                int offset, int limit,
                                AnalysisLoadedImage *out, int max_out,
                                int *out_total);

// scan_offset/scan_size 相对所选镜像的 __text。单次最多扫描 48MB；超大镜像通过
// next_scan_offset 继续，避免设备端一次性重负载。
typedef struct {
    uint64_t text_start;
    uint64_t text_end;
    uint64_t scan_start;
    uint64_t scan_end;
    uint64_t scan_offset;
    uint64_t next_scan_offset;
    uint64_t bytes_requested;
    uint64_t bytes_read;
    uint64_t scanned_insns;
    uint32_t unreadable_pages;
    uint32_t partial_pages;
    uint32_t warmup_bytes;
    int      has_more;
    int      result_limit_reached;
    int      scan_size_capped;
    // 快照分配前的宿主可用内存检查: 不足时拒绝扫描(不分配), 避免把宿主 App 顶到 jetsam 阈值。
    int      insufficient_memory;
    uint64_t available_memory;   // os_proc_available_memory() 读数, 0=未知
} AnalysisScanInfo;

// ============================================================
// 交叉引用 (xref) —— tier-1: 仅「直接 BL 调用」
// ============================================================
//
// 只扫某镜像 __TEXT,__text 里的 `bl imm`, 解析其目标, 建立「谁调用了 target」。
// 不做 BLR/BR 间接调用、不做 string/selector 引用、不做 CFG、不持久化。
// 活进程优势: stub → import 符号靠运行时已绑定的 GOT slot + dladdr 直接得到,
// 不解析 bind 信息; ADRP 页基址由 capstone 算好。lazy slot 未绑定则记为未知目标。

typedef struct {
    uint64_t call_site;          // BL 指令地址
    uint64_t target;             // BL 立即数目标 (可能落在 stub 段)
    uint64_t resolved_target;    // 经 stub/GOT 解析后的真实目标; 无 stub 时 == target
    char     kind[24];           // "call_direct" | "call_import_stub" | "call_objc_stub"
    char     resolved_name[256]; // 解析出的符号名(去前导下划线); 未知为空串
    // 归属(tier-1.5): 有 dladdr 符号 → 符号名; 否则经 LC_FUNCTION_STARTS → "sub_<runtime>"; 都无 → 空串。
    char     from_func[256];     // 函数名 或 "sub_<runtime-hex>"; 未知为空串
    uint64_t from_offset;        // call_site 相对函数起点的偏移
    uint64_t from_func_start;    // 函数起点运行时地址; 0=未知
    uint64_t from_func_vmaddr;   // 函数起点 vmaddr(去 slide, 稳定 ID, 跨 ASLR 不变); 0=未知
    char     insn_text[64];      // 如 "bl #0x1029ac1f8"
} AnalysisXref;

// 在 image_query 指定镜像(名字子串; NULL/"" = 主程序)的 __text 里查找所有直接 BL
// 到目标的调用点。目标二选一: sym_name(经 dlsym 解析) 或 target_addr(!=0)。
//   out/max_results:  命中记录缓冲(按 max_results 截断)
//   out_query_addr:   回填目标运行时地址(dlsym 结果或 target_addr)
//   out_image:        回填实际扫描的镜像短名
//   out_scan:         回填实际覆盖范围、可读页和下一页 offset
// 返回命中数; -1 参数错误, -2 找不到镜像/__text, -3 符号无法解析,
// -4 scan_offset 越界, -5 无法分配有界快照。
int analysis_find_xrefs(const char *image_query,
                        const char *sym_name, uint64_t target_addr,
                        uint64_t scan_offset, uint64_t scan_size,
                        AnalysisXref *out, int max_results,
                        uint64_t *out_query_addr, char *out_image, size_t image_len,
                        AnalysisScanInfo *out_scan);

// ============================================================
// 字符串引用 (string ref) —— tier-2A
// ============================================================
//
// 扫某镜像 __text, 识别 ADRP+ADD(直接) / ADRP+LDR→指针槽(间接) 恢复出的数据地址,
// 若落在字符串 section(__cstring/__objc_methname/__objc_classname/__objc_methtype)
// 则建立「谁引用了这个字符串」。局部窗口回溯(按寄存器缓存最近 ADRP 页, 被写即失效),
// 不做跨基本块/跨函数数据流。归属复用 tier-1.5 的 function-starts。

typedef struct {
    uint64_t ref_site;           // 使用点(ADD/LDR 指令)地址
    char     from_func[256];     // 归属函数名 或 "sub_<runtime>"; 未知空串
    uint64_t from_offset;
    uint64_t from_func_start;
    uint64_t from_func_vmaddr;   // 稳定 ID(去 slide)
    uint64_t string_addr;        // 字符串运行时地址
    uint64_t string_vmaddr;      // 去 slide
    char     string[192];        // 字符串内容(截断)
    char     section[32];        // "__TEXT,__cstring" 等
    char     insn_text[64];      // 如 "add x0, x0, #0x8f0"
    int      indirect;           // 0=ADRP+ADD 直接; 1=ADRP+LDR 经指针槽
} AnalysisStringRef;

// 在 image_query 指定镜像的 __text 里查找字符串引用。目标二选一:
//   query_str(子串匹配字符串内容) 或 query_addr(!=0, 精确匹配字符串地址)。
// 返回命中数; -1 参数错误, -2 找不到镜像/__text。out_* 语义同 find_xrefs。
int analysis_find_string_refs(const char *image_query,
                              const char *query_str, uint64_t query_addr,
                              uint64_t scan_offset, uint64_t scan_size,
                              AnalysisStringRef *out, int max_results,
                              char *out_image, size_t image_len,
                              AnalysisScanInfo *out_scan);

// ============================================================
// selector 引用 (selector ref) —— tier-2B
// ============================================================
//
// 找「哪里把某 selector 用在了 objc 调用上」—— xref 站点是 objc 调用的 call_site,
// 不是单纯的 selref 加载。两条路径:
//   A 经典: adrp+ldr x1,[__objc_selrefs] → (blr/bl) objc_msgSend/Super/Super2  (x1 状态机)
//   B 现代: bl <__objc_stubs 的 objc_msgSend$sel>                              (stub 快路径)
// 只在 objc_msgSend 调用点报; x1 被覆盖或仅加载未调用不报; 只命中 __objc_methname 不报。
// 不还原 receiver。复用 tier-2A 的地址恢复 / 读串 / 归属能力。

typedef struct {
    uint64_t call_site;            // objc_msgSend 调用点
    uint64_t selector_load_site;   // selref 加载指令地址(路径A); 0=不适用
    uint64_t selector_slot;        // __objc_selrefs 槽地址(路径A); 0=不适用
    char     selector[256];        // selector 名; 拿不到为空串
    char     target[80];           // "_objc_msgSend" / "objc_msgSend$sel" / "objc_stub@0x.."
    char     target_kind[16];      // "objc_msgsend" | "objc_stub"
    char     selector_source[16];  // "__objc_selrefs" | "__objc_stubs"
    char     from_func[256];
    uint64_t from_offset;
    uint64_t from_func_start;
    uint64_t from_func_vmaddr;
    char     insn_text[64];        // 如 "blr x8" / "bl #0x..."
} AnalysisSelectorRef;

// 在 image_query 指定镜像的 __text 里查找 selector 调用引用。
//   selector_q: 目标 selector 名; match_mode: 0=精确 1=包含 2=前缀。
// 返回命中数; -1 参数错误, -2 找不到镜像/__text。out_* 语义同 find_xrefs。
int analysis_find_selector_refs(const char *image_query,
                                const char *selector_q, int match_mode,
                                uint64_t scan_offset, uint64_t scan_size,
                                AnalysisSelectorRef *out, int max_results,
                                char *out_image, size_t image_len,
                                AnalysisScanInfo *out_scan);

// ============================================================
// 内部函数调用图 (internal call xref) —— tier-3A
// ============================================================
//
// 只做「直接 BL 到本镜像 __text 内函数」的调用边: from_func → to_func。
// BL target 落在 __text 之外(__stubs/__auth_stubs/__objc_stubs = import/objc 调用)天然排除。
// 不做 BLR/BR/switch/tail-call 识别/basic block/CFG。BL 目标不一定是函数入口(branch island/
// thunk/block invoke), 故同时保留 target_addr 与 to_func_start + to_func_offset, 不假装是入口。

typedef struct {
    char     relation[8];        // 相对查询函数: "caller" | "callee"
    uint64_t call_site;          // BL 指令地址
    char     from_func[256];     // 主调函数名 或 "sub_<runtime>"; 未知空串
    uint64_t from_offset;
    uint64_t from_func_start;
    uint64_t from_func_vmaddr;
    uint64_t target_addr;        // BL 立即数目标(可能落在函数中间)
    char     to_func[256];       // 被调函数名 或 "sub_<runtime>"; 未知空串
    uint64_t to_offset;          // target_addr 相对 to_func_start 的偏移
    uint64_t to_func_start;
    uint64_t to_func_vmaddr;
    char     insn_text[64];      // 如 "bl #0x104900120"
} AnalysisFuncRef;

// 在 image_query 指定镜像的 __text 里查找 target_addr 所属函数的内部调用边。
//   direction: 0=callers(谁调用它) 1=callees(它调用谁) 2=both。
// 返回命中数; -1 参数错误, -2 找不到镜像/__text, -3 target_addr 无法归属到函数。
// out_query_start 回填查询函数的入口运行时地址。
int analysis_find_function_refs(const char *image_query,
                                uint64_t target_addr, int direction,
                                uint64_t scan_offset, uint64_t scan_size,
                                AnalysisFuncRef *out, int max_results,
                                char *out_image, size_t image_len,
                                uint64_t *out_query_start,
                                AnalysisScanInfo *out_scan);

// ============================================================
// 函数清单 (function inventory) —— tier-3B
// ============================================================
//
// 把内部依赖的 LC_FUNCTION_STARTS 对外暴露成函数清单。size 是「到下一个函数入口」的
// 近似值(非精确边界)。有 dladdr 符号用符号名, 否则 "sub_<runtime>"。

typedef struct {
    uint64_t start;        // 运行时入口地址
    uint64_t vmaddr;       // 去 slide, 稳定 ID
    uint64_t size;         // ≈ 下一个函数入口 - 本入口(近似)
    char     name[256];    // dladdr 符号名 或 "sub_<runtime>"
    int      has_symbol;   // 1=有真实符号(入口处), 0=sub_
} AnalysisFunction;

// 列出 image_query 指定镜像(NULL/"" = 主程序)的函数(来自 LC_FUNCTION_STARTS)。
//   name_query: 非空则按名字子串过滤; offset/limit: 分页(limit<=0 视为不限, 仍受 max_out 限)。
// 返回本次填充数; out_total 回填过滤后总数。-1 参数错误, -2 找不到镜像/__text。
// 无 LC_FUNCTION_STARTS 的镜像返回 0。
int analysis_list_functions(const char *image_query, const char *name_query,
                            int offset, int limit,
                            AnalysisFunction *out, int max_out,
                            char *out_image, size_t image_len, int *out_total);

#ifdef __cplusplus
}
#endif

#endif // ANALYSIS_H
