// analysis.m — 二进制分析实现
//
// capstone 反汇编 + vm_read_overwrite 安全读内存 + macho_dump 镜像枚举

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <string.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <pthread.h>
#include "capstone/capstone.h"
#include "analysis.h"
#include "macho_dump.h"

#include <os/proc.h>
#include <TargetConditionals.h>

#define ANALYSIS_MAX_READ   (64 * 1024)          // 单次读内存上限
#define ANALYSIS_MAX_SEARCH (256 * 1024 * 1024)  // search_memory 范围上限
#define ANALYSIS_MAX_XREF_SCAN (48ULL * 1024 * 1024)
// xref 默认窗口: 之前默认就是上限 48MB, 在 2~3GB 内存设备上单次 calloc 48MB 很容易把宿主顶到
// jetsam 阈值(实测单次 256MB 扫描会让系统可用内存掉 56MB)。默认降到 8MB, 需要更大窗口时显式传
// scan_size, 并受下面的可用内存检查约束。
#define ANALYSIS_DEFAULT_XREF_SCAN (8ULL * 1024 * 1024)
// 分配快照前必须留出的安全余量: 宿主 App 自身、系统与并发 hook 都需要内存。
#define ANALYSIS_SNAPSHOT_RESERVE  (64ULL * 1024 * 1024)

// 宿主进程剩余可用内存 (iOS 13+)。0 表示未知(不拦截)。
// 注意: os_proc_available_memory 在 macOS 上被标记为 unavailable, 不能只在运行时判断,
// 必须用编译期分支 —— 否则 mac 变体 / test-mcp 直接编译失败。
static uint64_t analysis_available_memory(void) {
#if TARGET_OS_OSX
    return 0;   // macOS: 无此 API, 视为未知
#else
    if (__builtin_available(iOS 13.0, *)) {
        return (uint64_t)os_proc_available_memory();
    }
    return 0;
#endif
}

// ============================================================
// Capstone 反汇编
// ============================================================

// 把 arch 字符串映射成 capstone 的 (arch, mode); 未识别时回退 arm64。
static void arch_to_cs(const char *arch, cs_arch *out_arch, cs_mode *out_mode) {
    cs_arch a = CS_ARCH_ARM64;
    cs_mode m = CS_MODE_ARM;
    if (arch) {
        if (strcmp(arch, "arm") == 0)        { a = CS_ARCH_ARM;   m = CS_MODE_ARM; }
        else if (strcmp(arch, "thumb") == 0) { a = CS_ARCH_ARM;   m = CS_MODE_THUMB; }
        // "arm64"/"aarch64"/其它 → 默认 arm64
    }
    *out_arch = a;
    *out_mode = m;
}

static void copy_text(char *out, size_t len, const char *value) {
    if (!out || len == 0) return;
    if (!value) value = "";
    strncpy(out, value, len - 1);
    out[len - 1] = '\0';
}

static const char *arm64_shift_name(arm64_shifter shift) {
    switch (shift) {
        case ARM64_SFT_LSL: return "lsl";
        case ARM64_SFT_MSL: return "msl";
        case ARM64_SFT_LSR: return "lsr";
        case ARM64_SFT_ASR: return "asr";
        case ARM64_SFT_ROR: return "ror";
        default: return "";
    }
}

static const char *arm64_ext_name(arm64_extender ext) {
    switch (ext) {
        case ARM64_EXT_UXTB: return "uxtb";
        case ARM64_EXT_UXTH: return "uxth";
        case ARM64_EXT_UXTW: return "uxtw";
        case ARM64_EXT_UXTX: return "uxtx";
        case ARM64_EXT_SXTB: return "sxtb";
        case ARM64_EXT_SXTH: return "sxth";
        case ARM64_EXT_SXTW: return "sxtw";
        case ARM64_EXT_SXTX: return "sxtx";
        default: return "";
    }
}

static const char *arm_shift_name(arm_shifter shift) {
    switch (shift) {
        case ARM_SFT_ASR: return "asr";
        case ARM_SFT_LSL: return "lsl";
        case ARM_SFT_LSR: return "lsr";
        case ARM_SFT_ROR: return "ror";
        case ARM_SFT_RRX: return "rrx";
        case ARM_SFT_ASR_REG: return "asr_reg";
        case ARM_SFT_LSL_REG: return "lsl_reg";
        case ARM_SFT_LSR_REG: return "lsr_reg";
        case ARM_SFT_ROR_REG: return "ror_reg";
        case ARM_SFT_RRX_REG: return "rrx_reg";
        default: return "";
    }
}

static void copy_reg_name(csh handle, unsigned int reg, char out[16]) {
    copy_text(out, 16, reg ? cs_reg_name(handle, reg) : "");
}

static void copy_arm64_operand(csh handle, const cs_arm64_op *src, AnalysisOperand *dst) {
    dst->raw_type = (uint16_t)src->type;
    dst->access = src->access;
    copy_text(dst->shift, sizeof(dst->shift), arm64_shift_name(src->shift.type));
    dst->shift_value = (uint8_t)(src->shift.value > UINT8_MAX ? UINT8_MAX : src->shift.value);
    copy_text(dst->extender, sizeof(dst->extender), arm64_ext_name(src->ext));
    switch (src->type) {
        case ARM64_OP_REG:
            dst->type = AnalysisOperandRegister;
            copy_reg_name(handle, src->reg, dst->reg);
            break;
        case ARM64_OP_IMM:
        case ARM64_OP_CIMM:
            dst->type = AnalysisOperandImmediate;
            dst->immediate = src->imm;
            break;
        case ARM64_OP_MEM:
            dst->type = AnalysisOperandMemory;
            copy_reg_name(handle, src->mem.base, dst->base);
            copy_reg_name(handle, src->mem.index, dst->index);
            dst->displacement = src->mem.disp;
            break;
        case ARM64_OP_FP:
            dst->type = AnalysisOperandFloatingPoint;
            dst->fp = src->fp;
            break;
        default:
            dst->type = AnalysisOperandOther;
            break;
    }
}

static void copy_arm_operand(csh handle, const cs_arm_op *src, AnalysisOperand *dst) {
    dst->raw_type = (uint16_t)src->type;
    dst->access = src->access;
    copy_text(dst->shift, sizeof(dst->shift), arm_shift_name(src->shift.type));
    dst->shift_value = (uint8_t)(src->shift.value > UINT8_MAX ? UINT8_MAX : src->shift.value);
    switch (src->type) {
        case ARM_OP_REG:
            dst->type = AnalysisOperandRegister;
            copy_reg_name(handle, (unsigned int)src->reg, dst->reg);
            break;
        case ARM_OP_IMM:
        case ARM_OP_CIMM:
        case ARM_OP_PIMM:
            dst->type = AnalysisOperandImmediate;
            dst->immediate = src->imm;
            break;
        case ARM_OP_MEM:
            dst->type = AnalysisOperandMemory;
            copy_reg_name(handle, (unsigned int)src->mem.base, dst->base);
            copy_reg_name(handle, (unsigned int)src->mem.index, dst->index);
            dst->displacement = src->mem.disp;
            break;
        case ARM_OP_FP:
            dst->type = AnalysisOperandFloatingPoint;
            dst->fp = src->fp;
            break;
        default:
            dst->type = AnalysisOperandOther;
            break;
    }
}

static void copy_disassembled_insn(csh handle, cs_arch arch,
                                   const cs_insn *insn, AnalysisInsn *out) {
    memset(out, 0, sizeof(*out));
    out->address = insn->address;
    out->id = insn->id;
    out->size = (uint8_t)(insn->size > UINT8_MAX ? UINT8_MAX : insn->size);
    copy_text(out->mnemonic, sizeof(out->mnemonic), insn->mnemonic);
    copy_text(out->op_str, sizeof(out->op_str), insn->op_str);
    size_t nb = insn->size < sizeof(out->bytes) ? insn->size : sizeof(out->bytes);
    memcpy(out->bytes, insn->bytes, nb);
    if (!insn->detail) return;

    out->is_jump = cs_insn_group(handle, insn, CS_GRP_JUMP) ? 1 : 0;
    out->is_call = cs_insn_group(handle, insn, CS_GRP_CALL) ? 1 : 0;
    out->is_return = cs_insn_group(handle, insn, CS_GRP_RET) ? 1 : 0;
    out->writeback = insn->detail->writeback ? 1 : 0;

    uint8_t source_count = 0;
    if (arch == CS_ARCH_ARM64) {
        const cs_arm64 *detail = &insn->detail->arm64;
        source_count = detail->op_count;
        out->writes_flags = detail->update_flags ? 1 : 0;
        out->operand_count = source_count > ANALYSIS_MAX_OPERANDS ? ANALYSIS_MAX_OPERANDS : source_count;
        for (uint8_t i = 0; i < out->operand_count; i++)
            copy_arm64_operand(handle, &detail->operands[i], &out->operands[i]);
    } else if (arch == CS_ARCH_ARM) {
        const cs_arm *detail = &insn->detail->arm;
        source_count = detail->op_count;
        out->writes_flags = detail->update_flags ? 1 : 0;
        out->operand_count = source_count > ANALYSIS_MAX_OPERANDS ? ANALYSIS_MAX_OPERANDS : source_count;
        for (uint8_t i = 0; i < out->operand_count; i++)
            copy_arm_operand(handle, &detail->operands[i], &out->operands[i]);
    }
    out->operands_truncated = source_count > ANALYSIS_MAX_OPERANDS ? 1 : 0;
}

int analysis_disassemble(const uint8_t *code, size_t size, uint64_t address,
                         const char *arch, AnalysisInsn *out, int max_count) {
    if (!code || size == 0 || !out || max_count <= 0) return -1;

    cs_arch cs_a; cs_mode cs_m;
    arch_to_cs(arch, &cs_a, &cs_m);

    csh handle = 0;
    if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK) return -1;
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&handle);
        return -1;
    }

    cs_insn *insn = cs_malloc(handle);
    if (!insn) { cs_close(&handle); return -1; }

    int count = 0;
    const uint8_t *p = code;
    size_t remaining = size;
    uint64_t cur = address;

    while (count < max_count && remaining > 0 &&
           cs_disasm_iter(handle, &p, &remaining, &cur, insn)) {
        copy_disassembled_insn(handle, cs_a, insn, &out[count]);
        count++;
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return count;
}

int analysis_disassemble_at(uint64_t address, size_t size, const char *arch,
                            AnalysisInsn *out, int max_count) {
    if (!out || max_count <= 0 || size == 0) return -1;
    if (size > ANALYSIS_MAX_READ) size = ANALYSIS_MAX_READ;

    uint8_t *buf = malloc(size);
    if (!buf) return -1;

    // vm_read_overwrite: 目标区域不可读时返回错误码而非触发 SIGSEGV。
    vm_size_t outsize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address, (vm_size_t)size,
                                         (vm_address_t)buf, &outsize);
    if (kr != KERN_SUCCESS || outsize == 0) {
        free(buf);
        return -2;   // 内存不可读
    }

    int n = analysis_disassemble(buf, (size_t)outsize, address, arch, out, max_count);
    free(buf);
    return n;
}

int analysis_disassemble_func(uint64_t address, size_t max_bytes, const char *arch,
                              AnalysisInsn *out, int max_count) {
    if (!out || max_count <= 0) return -1;
    if (max_bytes == 0 || max_bytes > ANALYSIS_MAX_READ) max_bytes = ANALYSIS_MAX_READ;

    uint8_t *buf = malloc(max_bytes);
    if (!buf) return -1;
    vm_size_t outsize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address, (vm_size_t)max_bytes,
                                         (vm_address_t)buf, &outsize);
    if (kr != KERN_SUCCESS || outsize == 0) { free(buf); return -2; }

    cs_arch cs_a; cs_mode cs_m;
    arch_to_cs(arch, &cs_a, &cs_m);
    csh handle = 0;
    if (cs_open(cs_a, cs_m, &handle) != CS_ERR_OK) { free(buf); return -1; }
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&handle);
        free(buf);
        return -1;
    }
    cs_insn *insn = cs_malloc(handle);
    if (!insn) { cs_close(&handle); free(buf); return -1; }

    int count = 0;
    const uint8_t *p = buf;
    size_t remaining = (size_t)outsize;
    uint64_t cur = address;
    while (count < max_count && remaining > 0 &&
           cs_disasm_iter(handle, &p, &remaining, &cur, insn)) {
        copy_disassembled_insn(handle, cs_a, insn, &out[count]);
        count++;
        // 函数边界启发式: 遇到 ret 收尾 (arm64 函数以 ret 结束)。
        if (strcmp(insn->mnemonic, "ret") == 0) break;
    }

    cs_free(insn, 1);
    cs_close(&handle);
    free(buf);
    return count;
}

// ============================================================
// 符号 / 内存
// ============================================================

// 取路径 basename 到 buf (dli_fname 是完整路径)。
static void copy_basename(const char *path, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return;
    if (!path) { buf[0] = '\0'; return; }
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    const char *b = basename(tmp);
    strncpy(buf, b ?: "?", buflen - 1);
    buf[buflen - 1] = '\0';
}

int analysis_resolve_symbol(const char *name, uint64_t *out_addr,
                            char *out_image, size_t image_len) {
    if (!name || !out_addr) return -1;
    void *p = dlsym(RTLD_DEFAULT, name);
    if (!p) return -1;
    *out_addr = (uint64_t)(uintptr_t)p;
    if (out_image && image_len) {
        Dl_info info;
        if (dladdr(p, &info) && info.dli_fname) copy_basename(info.dli_fname, out_image, image_len);
        else { out_image[0] = '\0'; }
    }
    return 0;
}

int analysis_symbolicate(uint64_t addr, char *out_sym, size_t sym_len,
                         uint64_t *out_offset, char *out_image, size_t image_len,
                         uint64_t *out_normalized) {
    AnalysisAddressInfo info;
    if (analysis_address_info(addr, &info) != 0 || !info.symbol[0]) return -1;
    if (out_normalized) *out_normalized = info.normalized_address;
    if (out_sym && sym_len) {
        strncpy(out_sym, info.symbol, sym_len - 1);
        out_sym[sym_len - 1] = '\0';
    }
    if (out_offset) *out_offset = info.symbol_offset;
    if (out_image && image_len) {
        strncpy(out_image, info.image, image_len - 1);
        out_image[image_len - 1] = '\0';
    }
    return 0;
}

int analysis_read_memory(uint64_t addr, size_t size, uint8_t *out_buf, size_t buf_cap) {
    if (!out_buf || size == 0 || buf_cap == 0) return -1;
    if (size > buf_cap) size = buf_cap;
    if (size > ANALYSIS_MAX_READ) size = ANALYSIS_MAX_READ;
    vm_size_t outsize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)addr, (vm_size_t)size,
                                         (vm_address_t)out_buf, &outsize);
    if (kr != KERN_SUCCESS) return -2;
    return (int)outsize;
}

int analysis_search_memory(uint64_t addr, size_t length,
                           const uint8_t *pattern, size_t plen,
                           uint64_t *out_hits, int max_hits) {
    if (!pattern || plen == 0 || !out_hits || max_hits <= 0) return -1;
    if (length > ANALYSIS_MAX_SEARCH) length = ANALYSIS_MAX_SEARCH;

    const size_t CHUNK = 64 * 1024;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) return -1;

    int hits = 0;
    uint64_t pos = addr;
    uint64_t end = addr + length;
    while (pos < end && hits < max_hits) {
        size_t want = (size_t)((end - pos) < CHUNK ? (end - pos) : CHUNK);
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                             (vm_address_t)pos, (vm_size_t)want,
                                             (vm_address_t)buf, &got);
        if (kr != KERN_SUCCESS || got == 0) {
            // 不可读页: 跳过整块继续 (跨该间隙的匹配会漏, 可接受)。
            pos += CHUNK;
            continue;
        }
        if (got >= plen) {
            const uint8_t *base = buf;
            const uint8_t *hit;
            size_t remain = (size_t)got;
            while (hits < max_hits &&
                   (hit = memmem(base, remain, pattern, plen)) != NULL) {
                out_hits[hits++] = pos + (uint64_t)(hit - buf);
                size_t consumed = (size_t)(hit - base) + 1;
                base += consumed;
                remain = (size_t)got - (size_t)(base - buf);
                if (remain < plen) break;
            }
        }
        // 重叠 plen-1 字节, 避免跨块边界漏匹配 (间隙块除外)。
        pos += (got > (plen - 1)) ? (got - (plen - 1)) : got;
    }
    free(buf);
    return hits;
}

// ============================================================
// Mach-O 镜像枚举 (复用 macho_dump)
// ============================================================

int analysis_list_macho_images(AnalysisMachoImage *out, int max_count) {
    if (!out || max_count <= 0) return -1;

    NSArray<DHDumpImage *> *images = dh_dump_list_images();
    int count = 0;
    for (DHDumpImage *img in images) {
        if (count >= max_count) break;
        AnalysisMachoImage *o = &out[count];

        strncpy(o->name, img.name.UTF8String ?: "?", sizeof(o->name) - 1);
        o->name[sizeof(o->name) - 1] = '\0';
        strncpy(o->kind, img.kind.UTF8String ?: "?", sizeof(o->kind) - 1);
        o->kind[sizeof(o->kind) - 1] = '\0';

        o->load_address = (uint64_t)(uintptr_t)img.header;
        o->encrypted = (img.cryptid != 0) ? 1 : 0;
        o->cryptid = img.cryptid;
        o->cryptsize = img.cryptsize;
        count++;
    }
    return count;
}

static void loaded_image_uuid(const struct mach_header_64 *mh, char out[37]) {
    out[0] = '\0';
    const uint8_t *cur = (const uint8_t *)mh + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmdsize < sizeof(*lc)) return;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const uint8_t *u = ((const struct uuid_command *)lc)->uuid;
            snprintf(out, 37,
                     "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                     u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                     u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
            return;
        }
        cur += lc->cmdsize;
    }
}

static void loaded_image_install_name(const struct mach_header_64 *mh,
                                      char *out, size_t len) {
    if (!out || len == 0) return;
    out[0] = '\0';
    const uint8_t *cur = (const uint8_t *)mh + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmdsize < sizeof(*lc)) return;
        if (lc->cmd == LC_ID_DYLIB && lc->cmdsize >= sizeof(struct dylib_command)) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            if (dc->dylib.name.offset < dc->cmdsize) {
                const char *name = (const char *)dc + dc->dylib.name.offset;
                size_t avail = dc->cmdsize - dc->dylib.name.offset;
                size_t n = strnlen(name, avail);
                if (n < avail) {
                    size_t copy = n < len - 1 ? n : len - 1;
                    memcpy(out, name, copy); out[copy] = '\0';
                }
            }
            return;
        }
        cur += lc->cmdsize;
    }
}

static NSString *loaded_image_real_path(const struct mach_header_64 *mh,
                                        const char *dyldPath) {
    NSString *path = dyldPath ? @(dyldPath) : @"";
    // hook_dyld 对隐藏镜像只改名不改 header/index。LC_ID_DYLIB 仍保留真实 install name，
    // 当 dyld 名被统一伪装成 libSystem 时用它恢复工具内部的镜像身份。
    if ([path isEqualToString:@"/usr/lib/libSystem.B.dylib"] && mh->filetype == MH_DYLIB) {
        char installName[1024] = {0};
        loaded_image_install_name(mh, installName, sizeof(installName));
        if (installName[0] && strcmp(installName, "/usr/lib/libSystem.B.dylib") != 0)
            path = @(installName);
    }
    return path;
}

static void loaded_image_metadata(const struct mach_header_64 *mh, intptr_t slide,
                                  AnalysisLoadedImage *o) {
    const uint8_t *cur = (const uint8_t *)mh + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmdsize < sizeof(*lc)) return;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            BOOL executableSegment = strncmp(sg->segname, "__TEXT", sizeof(sg->segname)) == 0 ||
                                     strncmp(sg->segname, "__TEXT_EXEC", sizeof(sg->segname)) == 0;
            if (executableSegment && sg->vmsize > 0) {
                uint64_t lo = (uint64_t)((intptr_t)sg->vmaddr + slide);
                uint64_t hi = lo + sg->vmsize;
                if (!o->text_start || lo < o->text_start) o->text_start = lo;
                if (hi > o->text_end) o->text_end = hi;
            }
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 &&
                   lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *ei =
                (const struct encryption_info_command_64 *)lc;
            o->cryptid = ei->cryptid;
            o->cryptsize = ei->cryptsize;
        }
        cur += lc->cmdsize;
    }
}

int analysis_list_loaded_images(const char *query, int include_system,
                                int offset, int limit,
                                AnalysisLoadedImage *out, int max_out,
                                int *out_total) {
    if (out_total) *out_total = 0;
    if (!out || max_out <= 0) return -1;
    if (offset < 0) offset = 0;
    if (limit <= 0 || limit > max_out) limit = max_out;

    NSString *bundlePath = NSBundle.mainBundle.bundlePath ?: @"";
    NSString *q = query && query[0] ? [@(query) lowercaseString] : nil;
    uint32_t count = _dyld_image_count();
    int total = 0, added = 0;
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        const char *cpath = _dyld_get_image_name(i);
        if (!mh || mh->magic != MH_MAGIC_64 || !cpath) continue;
        NSString *path = loaded_image_real_path(mh, cpath);
        NSString *name = path.lastPathComponent ?: path;
        BOOL app = (bundlePath.length && [path hasPrefix:bundlePath]) ||
                   [path hasPrefix:@"@executable_path/"] || [path hasPrefix:@"@rpath/"];
        BOOL system = [path hasPrefix:@"/System/"] || [path hasPrefix:@"/usr/lib/"];
        if (!include_system && system) continue;
        if (q && [path.lowercaseString rangeOfString:q].location == NSNotFound &&
            [name.lowercaseString rangeOfString:q].location == NSNotFound) continue;
        if (total++ < offset) continue;
        if (added >= limit || added >= max_out) continue;

        AnalysisLoadedImage *o = &out[added++];
        memset(o, 0, sizeof(*o));
        o->dyld_index = (int)i;
        o->is_main = (mh->filetype == MH_EXECUTE);
        o->load_address = (uint64_t)(uintptr_t)mh;
        o->slide = (int64_t)_dyld_get_image_vmaddr_slide(i);
        o->filetype = mh->filetype;
        strncpy(o->scope, app ? "app" : (system ? "system" : "external"), sizeof(o->scope) - 1);
        strncpy(o->name, name.UTF8String ?: "?", sizeof(o->name) - 1);
        strncpy(o->path, path.UTF8String ?: "?", sizeof(o->path) - 1);
        loaded_image_uuid(mh, o->uuid);
        loaded_image_metadata(mh, (intptr_t)o->slide, o);
    }
    if (out_total) *out_total = total;
    return added;
}


// ============================================================
// 交叉引用 (xref) —— tier-1: 直接 BL 调用
// ============================================================

// dli_fname 的 basename 指针 (只读, 不拷贝)。
static const char *base_ptr(const char *p) {
    const char *b = p ? p : "";
    for (const char *s = b; *s; s++) if (*s == '/') b = s + 1;
    return b;
}

// dladdr 取去下划线的符号名到 buf; 命中回填 *out_off(相对符号起点偏移) 返回 1, 否则置空串返回 0。
static int name_at(uint64_t addr, char *buf, size_t buflen, uint64_t *out_off) {
    if (buf && buflen) buf[0] = '\0';
    if (out_off) *out_off = 0;
    Dl_info info;
    if (!dladdr((void *)(uintptr_t)addr, &info) || !info.dli_sname) return 0;
    const char *s = info.dli_sname;
    if (s[0] == '_') s++;
    if (!s[0]) return 0;
    if (buf && buflen) { strncpy(buf, s, buflen - 1); buf[buflen - 1] = '\0'; }
    if (out_off && info.dli_saddr) *out_off = addr - (uint64_t)(uintptr_t)info.dli_saddr;
    return 1;
}

// 选镜像: image_query 为名字子串; NULL/"" 选主程序(MH_EXECUTE)。回填 slide/短名。
static const struct mach_header_64 *xref_select_image(const char *q, intptr_t *slideOut,
                                                      char *nameOut, size_t nameLen) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        const char *bn = base_ptr(_dyld_get_image_name(i));
        if (q && q[0]) { if (!strstr(bn, q)) continue; }
        else if (mh->filetype != MH_EXECUTE) continue;   // 默认主程序
        if (slideOut) *slideOut = _dyld_get_image_vmaddr_slide(i);
        if (nameOut && nameLen) { strncpy(nameOut, bn, nameLen - 1); nameOut[nameLen - 1] = '\0'; }
        return mh;
    }
    return NULL;
}

// 取镜像内某 section 的运行时 [start,end)。不存在或空返回 0。
static int xref_sect_range(const struct mach_header_64 *mh, intptr_t slide,
                           const char *seg, const char *sect,
                           uint64_t *start, uint64_t *end) {
    const struct section_64 *s = getsectbynamefromheader_64(mh, seg, sect);
    if (!s || s->size == 0) return 0;
    *start = (uint64_t)((uintptr_t)s->addr + (uintptr_t)slide);
    *end   = *start + s->size;
    return 1;
}

// 以真实 dyld header + 可执行段范围定位地址所属镜像。不能只信 dladdr 的最近符号，
// stripped 大镜像里它可能指向数 MB 之外的导出符号。
static const struct mach_header_64 *image_containing_address(uint64_t addr,
                                                              intptr_t *slide_out,
                                                              char *name_out, size_t name_len,
                                                              uint64_t *text_lo, uint64_t *text_hi) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        AnalysisLoadedImage meta; memset(&meta, 0, sizeof(meta));
        loaded_image_metadata(mh, slide, &meta);
        if (addr < meta.text_start || addr >= meta.text_end) continue;

        if (slide_out) *slide_out = slide;
        if (name_out && name_len) {
            NSString *path = loaded_image_real_path(mh, _dyld_get_image_name(i));
            copy_basename(path.UTF8String, name_out, name_len);
        }
        if (text_lo && text_hi) {
            *text_lo = 0; *text_hi = 0;
            if (!xref_sect_range(mh, slide, "__TEXT", "__text", text_lo, text_hi))
                xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", text_lo, text_hi);
        }
        return mh;
    }
    return NULL;
}

static inline int in_range(uint64_t a, uint64_t lo, uint64_t hi) { return lo && a >= lo && a < hi; }

// tier-1 PAC 处理: arm64 上是空操作; arm64e 上抹掉高位鉴权位到 48-bit VA。
static inline uint64_t strip_pac(uint64_t p) { return p & 0x0000FFFFFFFFFFFFULL; }

// 安全读 8 字节指针。成功返回 1。
static int read_ptr(uint64_t addr, uint64_t *out) {
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)addr, 8,
                          (vm_address_t)out, &got) != KERN_SUCCESS || got != 8) return 0;
    return 1;
}

// 反汇编 stub 起始处若干条, 求它加载的 GOT/auth-GOT slot 地址 (ADRP + LDR 同寄存器)。
// 覆盖 __stubs 的 adrp/ldr 与 __auth_stubs 的 adrp/ldr/braa 变种。成功返回 1。
static int decode_stub_slot(csh h, cs_insn *insn, uint64_t stub_addr, uint64_t *slot_out) {
    uint8_t buf[32];
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)stub_addr, sizeof(buf),
                          (vm_address_t)buf, &got) != KERN_SUCCESS || got < 8) return 0;
    const uint8_t *p = buf; size_t rem = (size_t)got; uint64_t cur = stub_addr;
    int adrp_reg = -1; uint64_t page = 0; int steps = 0;
    while (steps < 6 && cs_disasm_iter(h, &p, &rem, &cur, insn)) {
        steps++;
        cs_arm64 *a = &insn->detail->arm64;
        if (insn->id == ARM64_INS_ADRP && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            adrp_reg = a->operands[0].reg;
            page = (uint64_t)a->operands[1].imm;      // capstone 已算好页基址
        } else if (insn->id == ARM64_INS_LDR && adrp_reg >= 0 && a->op_count >= 2 &&
                   a->operands[1].type == ARM64_OP_MEM &&
                   a->operands[1].mem.base == (arm64_reg)adrp_reg) {
            *slot_out = page + (uint64_t)a->operands[1].mem.disp;
            return 1;
        }
    }
    return 0;
}

// ---- LC_FUNCTION_STARTS 归属 (tier-1.5) ----
// 说明: FUNCTION_STARTS 是 ULEB128 delta 序列, 从 __TEXT 段 vmaddr 起累加得每个函数入口偏移。
// 数据位置仍走 __LINKEDIT 映射(linkedit_base + dataoff), 不能把 dataoff 当 runtime 地址。
// 只做「call_site 二分归属到最近函数入口」, 不恢复函数边界(end 用下一个入口近似)。

typedef struct { uint64_t runtime; uint64_t vmaddr; } FuncStart;

typedef struct FuncStartsCache {
    const struct mach_header_64 *mh;   // 缓存键
    FuncStart *arr;                    // 按地址升序(构造即有序)
    size_t     count;
    uint64_t   text_hi;                // 末函数 end 兜底 = __text 运行时上界
    struct FuncStartsCache *next;
} FuncStartsCache;

static FuncStartsCache *g_fs_cache = NULL;
static pthread_mutex_t  g_fs_lock  = PTHREAD_MUTEX_INITIALIZER;

static uint64_t read_uleb(const uint8_t **pp, const uint8_t *end) {
    uint64_t result = 0; int bit = 0;
    while (*pp < end) {
        uint8_t b = *(*pp)++;
        if (bit <= 63) result |= ((uint64_t)(b & 0x7f)) << bit;
        bit += 7;
        if (!(b & 0x80)) break;
    }
    return result;
}

// 解析一个镜像的 FUNCTION_STARTS(未命中缓存则构造)。始终返回一个 cache 条目(可能 count==0)。
static FuncStartsCache *func_starts_for(const struct mach_header_64 *mh, intptr_t slide, uint64_t text_hi) {
    pthread_mutex_lock(&g_fs_lock);
    for (FuncStartsCache *c = g_fs_cache; c; c = c->next)
        if (c->mh == mh) { pthread_mutex_unlock(&g_fs_lock); return c; }

    FuncStartsCache *nc = calloc(1, sizeof(FuncStartsCache));
    if (!nc) { pthread_mutex_unlock(&g_fs_lock); return NULL; }
    nc->mh = mh; nc->text_hi = text_hi;

    uint64_t text_vmaddr = 0; int have_text = 0;
    const struct segment_command_64 *linkedit = NULL;
    const struct linkedit_data_command *fs = NULL;
    const uint8_t *cmds = (const uint8_t *)mh + sizeof(struct mach_header_64);
    const uint8_t *cend = cmds + mh->sizeofcmds;
    const uint8_t *p = cmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (p + sizeof(struct load_command) > cend) break;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command) || p + lc->cmdsize > cend) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) { text_vmaddr = sg->vmaddr; have_text = 1; }
            else if (strcmp(sg->segname, "__LINKEDIT") == 0) linkedit = sg;
        } else if (lc->cmd == LC_FUNCTION_STARTS) {
            fs = (const struct linkedit_data_command *)lc;
        }
        p += lc->cmdsize;
    }

    if (have_text && linkedit && fs && fs->datasize > 0 &&
        fs->dataoff >= linkedit->fileoff &&
        (uint64_t)fs->dataoff + fs->datasize <= (uint64_t)linkedit->fileoff + linkedit->filesize) {
        uintptr_t le_base = (uintptr_t)slide + (uintptr_t)linkedit->vmaddr - (uintptr_t)linkedit->fileoff;
        const uint8_t *data = (const uint8_t *)(le_base + fs->dataoff);
        const uint8_t *dend = data + fs->datasize;
        // 两遍: 先数个数(delta==0 结束), 再填充。
        size_t n = 0;
        for (const uint8_t *q = data; q < dend; ) { if (read_uleb(&q, dend) == 0) break; n++; }
        if (n > 0) {
            nc->arr = malloc(n * sizeof(FuncStart));
            if (nc->arr) {
                uint64_t cum = 0; size_t idx = 0;
                for (const uint8_t *q = data; q < dend && idx < n; ) {
                    uint64_t d = read_uleb(&q, dend);
                    if (d == 0) break;
                    cum += d;
                    nc->arr[idx].vmaddr  = text_vmaddr + cum;
                    nc->arr[idx].runtime = text_vmaddr + (uint64_t)slide + cum;
                    idx++;
                }
                nc->count = idx;
            }
        }
    }

    nc->next = g_fs_cache; g_fs_cache = nc;
    pthread_mutex_unlock(&g_fs_lock);
    return nc;
}

// 二分: addr 归属到 <= addr 的最大函数入口; end 用下一个入口(末个用 text_hi)近似。
// 落在函数间隙外(>= 近似 end)不强行归属。命中返回 1。
static int resolve_func_bounds(FuncStartsCache *c, uint64_t addr,
                               uint64_t *start_rt, uint64_t *end_rt,
                               uint64_t *start_vm, uint64_t *off) {
    if (!c || c->count == 0 || addr < c->arr[0].runtime) return 0;
    size_t lo = 0, hi = c->count;
    while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (c->arr[mid].runtime <= addr) lo = mid + 1; else hi = mid; }
    size_t idx = lo - 1;
    uint64_t fend = (idx + 1 < c->count) ? c->arr[idx + 1].runtime : c->text_hi;
    if (fend && addr >= fend) return 0;
    *start_rt = c->arr[idx].runtime;
    if (end_rt) *end_rt = fend;
    *start_vm = c->arr[idx].vmaddr;
    *off = addr - c->arr[idx].runtime;
    return 1;
}

static int resolve_func(FuncStartsCache *c, uint64_t addr,
                        uint64_t *start_rt, uint64_t *start_vm, uint64_t *off) {
    return resolve_func_bounds(c, addr, start_rt, NULL, start_vm, off);
}

int analysis_address_info(uint64_t addr, AnalysisAddressInfo *out) {
    if (!addr || !out) return -1;
    memset(out, 0, sizeof(*out));
    strncpy(out->confidence, "none", sizeof(out->confidence) - 1);

    uint64_t normalized = addr;
    intptr_t slide = 0;
    uint64_t text_lo = 0, text_hi = 0;
    const struct mach_header_64 *mh = image_containing_address(
        normalized, &slide, out->image, sizeof(out->image), &text_lo, &text_hi);
    uint64_t stripped = strip_pac(addr);
    if (!mh && stripped != addr) {
        normalized = stripped;
        mh = image_containing_address(normalized, &slide, out->image, sizeof(out->image),
                                      &text_lo, &text_hi);
    }
    out->normalized_address = normalized;

    if (mh) {
        out->address_mapped = 1;
        if (in_range(normalized, text_lo, text_hi)) {
            FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);
            uint64_t start = 0, end = 0, vmaddr = 0, offset = 0;
            if (resolve_func_bounds(fc, normalized, &start, &end, &vmaddr, &offset)) {
                out->has_function = 1;
                out->function_start = start;
                out->function_end = end;
                out->function_vmaddr = vmaddr;
                out->function_offset = offset;
                out->symbol_offset = offset;

                char exact[sizeof(out->symbol)] = {0}; uint64_t exact_off = 0;
                if (name_at(start, exact, sizeof(exact), &exact_off) && exact_off == 0) {
                    strncpy(out->symbol, exact, sizeof(out->symbol) - 1);
                    strncpy(out->symbol_source, "dladdr_exact", sizeof(out->symbol_source) - 1);
                    out->has_symbol = 1;
                } else {
                    snprintf(out->symbol, sizeof(out->symbol), "sub_%llx", start);
                    strncpy(out->symbol_source, "lc_function_starts", sizeof(out->symbol_source) - 1);
                }
                strncpy(out->confidence, "high", sizeof(out->confidence) - 1);
                return 0;
            }
        }
    }

    // 无 FUNCTION_STARTS 或地址不在 __text 时才退回 dladdr。此路径明确标低可信，
    // 调用方不得把 nearest symbol 当作已确认的函数边界。
    Dl_info dl;
    memset(&dl, 0, sizeof(dl));
    if (dladdr((void *)(uintptr_t)normalized, &dl) && dl.dli_saddr && dl.dli_sname) {
        const char *s = dl.dli_sname;
        if (s[0] == '_') s++;
        if (s[0]) {
            strncpy(out->symbol, s, sizeof(out->symbol) - 1);
            out->symbol_offset = normalized - (uint64_t)(uintptr_t)dl.dli_saddr;
            strncpy(out->symbol_source, "dladdr_nearest", sizeof(out->symbol_source) - 1);
            strncpy(out->confidence, "low", sizeof(out->confidence) - 1);
            out->has_symbol = 1;
            if (!out->image[0]) copy_basename(dl.dli_fname, out->image, sizeof(out->image));
            return 0;
        }
    }

    if (mh) {
        strncpy(out->symbol_source, "image", sizeof(out->symbol_source) - 1);
        return 0;
    }
    return -1;
}

// 把 site 归属到函数: 先用 FUNCTION_STARTS 定边界，仅接受恰好落在入口的 dladdr 符号。
// 这样 stripped 大镜像中的“最近导出符号 + 数 MB 偏移”不会污染函数归属。
static void attribute_addr(FuncStartsCache *fc, intptr_t slide, uint64_t site,
                           char *from_func, size_t ff_len, uint64_t *off,
                           uint64_t *start, uint64_t *vm) {
    from_func[0] = '\0'; *off = 0; *start = 0; *vm = 0;
    uint64_t frt = 0, fvm = 0, foff = 0;
    if (resolve_func(fc, site, &frt, &fvm, &foff)) {
        char sym[256] = {0}; uint64_t symoff = 0;
        if (name_at(frt, sym, sizeof(sym), &symoff) && symoff == 0) {
            strncpy(from_func, sym, ff_len - 1); from_func[ff_len - 1] = '\0';
        } else {
            snprintf(from_func, ff_len, "sub_%llx", frt);
        }
        *off = foff; *start = frt; *vm = fvm;
        return;
    }
    char sym[256] = {0}; uint64_t symoff = 0;
    if (name_at(site, sym, sizeof(sym), &symoff)) {
        strncpy(from_func, sym, ff_len - 1); from_func[ff_len - 1] = '\0';
        *off = symoff; *start = site - symoff; *vm = *start - (uint64_t)slide;
    }
}

static void attribute_call_site(FuncStartsCache *fc, intptr_t slide, AnalysisXref *r) {
    attribute_addr(fc, slide, r->call_site, r->from_func, sizeof(r->from_func),
                   &r->from_offset, &r->from_func_start, &r->from_func_vmaddr);
}

// 把 [lo, hi) 按 16KB 页块 vm_read_overwrite 快照到堆缓冲(不可读页保持 0)。
// 关键安全措施: xref 扫描不能直接解引用 __text 裸指针 —— 扫描要数秒, 期间目标镜像被并发
// dlclose/unmap 就会 SIGSEGV 崩宿主(TOCTOU)。快照后只碰副本, 源被 unmap 也无妨; 不可读页
// 填 0(capstone 反汇编 0 是无害的 udf/andeq, 不产生 BL/取址)。calloc 失败返回 NULL。
static uint8_t *snapshot_text(uint64_t lo, uint64_t hi, size_t *out_len,
                              AnalysisScanInfo *scan) {
    if (out_len) *out_len = 0;
    if (hi <= lo) return NULL;
    size_t len = (size_t)(hi - lo);
    // 内存闸门: 宿主可用内存不够(快照 + 64MB 余量)时直接拒绝, 不尝试分配。
    // 在 2~3GB 设备上, 盲目 calloc 48MB 会把被注入的宿主 App 推到 jetsam 阈值,
    // 表现为「App 闪退、系统无崩溃报告」。
    uint64_t avail = analysis_available_memory();
    if (scan) scan->available_memory = avail;
    if (avail > 0 && (uint64_t)len + ANALYSIS_SNAPSHOT_RESERVE > avail) {
        if (scan) scan->insufficient_memory = 1;
        return NULL;
    }
    uint8_t *buf = calloc(1, len);
    if (!buf) return NULL;
    const size_t PG = 16 * 1024;   // iOS 页 16KB; 某页不可读只丢这一页, 其余照读
    for (size_t off = 0; off < len; off += PG) {
        size_t want = (len - off < PG) ? (len - off) : PG;
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)(lo + off),
                                             (vm_size_t)want,
                                             (vm_address_t)(buf + off), &got);
        if (kr != KERN_SUCCESS || got == 0) {
            if (scan) scan->unreadable_pages++;
        } else {
            if (scan) scan->bytes_read += got;
            if ((size_t)got < want && scan) scan->partial_pages++;
        }
    }
    if (out_len) *out_len = len;
    return buf;
}

// 计算一次有界扫描窗口。scan_size=0 使用 8MB 默认窗口；显式更大值截到 48MB 上限。
// 返回 -4 表示 offset 已越过 __text。
static int prepare_scan(uint64_t text_lo, uint64_t text_hi,
                        uint64_t scan_offset, uint64_t scan_size,
                        AnalysisScanInfo *scan) {
    if (!scan || text_hi <= text_lo) return -1;
    memset(scan, 0, sizeof(*scan));
    uint64_t total = text_hi - text_lo;
    if (scan_offset >= total) return -4;
    scan->available_memory = analysis_available_memory();
    uint64_t size = scan_size ? scan_size : ANALYSIS_DEFAULT_XREF_SCAN;
    if (size > ANALYSIS_MAX_XREF_SCAN) {
        size = ANALYSIS_MAX_XREF_SCAN;
        scan->scan_size_capped = 1;
    }
    if (size > total - scan_offset) size = total - scan_offset;
    scan->text_start = text_lo;
    scan->text_end = text_hi;
    scan->scan_offset = scan_offset;
    scan->scan_start = text_lo + scan_offset;
    scan->scan_end = scan->scan_start + size;
    scan->bytes_requested = size;
    scan->has_more = scan->scan_end < text_hi;
    scan->next_scan_offset = scan->has_more ? scan->scan_end - text_lo : 0;
    return 0;
}

int analysis_find_xrefs(const char *image_query,
                        const char *sym_name, uint64_t target_addr,
                        uint64_t scan_offset, uint64_t scan_size,
                        AnalysisXref *out, int max_results,
                        uint64_t *out_query_addr, char *out_image, size_t image_len,
                        AnalysisScanInfo *out_scan) {
    if (out_scan) memset(out_scan, 0, sizeof(*out_scan));
    if (!out || max_results <= 0) return -1;
    if ((!sym_name || !sym_name[0]) && target_addr == 0) return -1;

    // 目标定位: 符号经 dlsym → 运行时地址; 或直接用 target_addr。
    char sym_deunder[256] = {0};
    uint64_t query_addr = target_addr;
    if (sym_name && sym_name[0]) {
        const char *nm = (sym_name[0] == '_') ? sym_name + 1 : sym_name;
        strncpy(sym_deunder, nm, sizeof(sym_deunder) - 1);
        void *pp = dlsym(RTLD_DEFAULT, nm);
        if (!pp && target_addr == 0) return -3;   // 符号解析不了且没给地址
        if (pp) query_addr = (uint64_t)(uintptr_t)pp;
    }
    if (out_query_addr) *out_query_addr = query_addr;

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    // __text 范围(优先 __TEXT,__text; 退回 __TEXT_EXEC,__text)。
    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    AnalysisScanInfo scan;
    int prep = prepare_scan(text_lo, text_hi, scan_offset, scan_size, &scan);
    if (prep != 0) return prep;

    // tier-1.5: 函数归属表(缺 LC_FUNCTION_STARTS 时 count==0, attribute_call_site 退回 dladdr/空)。
    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);

    // 目标分类需要的 stub 段范围(缺省为 0, in_range 会跳过)。
    uint64_t st_lo = 0, st_hi = 0, au_lo = 0, au_hi = 0, oc_lo = 0, oc_hi = 0;
    xref_sect_range(mh, slide, "__TEXT", "__stubs", &st_lo, &st_hi);
    xref_sect_range(mh, slide, "__TEXT", "__auth_stubs", &au_lo, &au_hi);
    xref_sect_range(mh, slide, "__TEXT", "__objc_stubs", &oc_lo, &oc_hi);

    // capstone: 主扫描 handle + 独立的 stub 解码 handle(各自 insn 状态互不干扰)。
    csh h = 0, hs = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return -1;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &hs) != CS_ERR_OK) { cs_close(&h); return -1; }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(hs, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(h);
    cs_insn *sinsn = cs_malloc(hs);
    if (!insn || !sinsn) {
        if (insn) cs_free(insn, 1);
        if (sinsn) cs_free(sinsn, 1);
        cs_close(&h); cs_close(&hs);
        return -1;
    }

    // __text 在本进程已映射(FairPlay 段运行时已解密), 直接按运行时地址反汇编, 不额外拷贝。
    size_t snap_len = 0;
    uint8_t *snap = snapshot_text(scan.scan_start, scan.scan_end, &snap_len, &scan);
    if (!snap) {
        cs_free(insn, 1); cs_free(sinsn, 1); cs_close(&h); cs_close(&hs);
        return -5;
    }
    const uint8_t *code = snap;
    size_t remaining = snap_len;
    uint64_t cur = scan.scan_start;
    uint64_t scanned = 0;
    int found = 0;

    while (cs_disasm_iter(h, &code, &remaining, &cur, insn)) {
        scanned++;
        if (insn->id != ARM64_INS_BL) continue;

        cs_arm64 *a = &insn->detail->arm64;
        if (a->op_count < 1 || a->operands[0].type != ARM64_OP_IMM) continue;
        uint64_t tgt = (uint64_t)a->operands[0].imm;

        // 分类 + 解析真实目标。
        const char *kind = "call_direct";
        uint64_t resolved = tgt;
        char rname[256] = {0}; uint64_t roff = 0;

        if (in_range(tgt, st_lo, st_hi) || in_range(tgt, au_lo, au_hi)) {
            kind = "call_import_stub";
            uint64_t slot = 0, raw = 0;
            if (decode_stub_slot(hs, sinsn, tgt, &slot) && read_ptr(slot, &raw)) {
                uint64_t stripped = strip_pac(raw);
                // 先按原值 dladdr, 不中再按 strip 后的值(arm64e auth 指针)。
                if (name_at(raw, rname, sizeof(rname), &roff)) resolved = raw;
                else if (name_at(stripped, rname, sizeof(rname), &roff)) resolved = stripped;
                else resolved = stripped;   // lazy 未绑定/无符号: 记裸值, 保留调用点
            }
            // slot 解不出: resolved 仍 == tgt(stub 地址), rname 空
        } else if (in_range(tgt, oc_lo, oc_hi)) {
            kind = "call_objc_stub";
            resolved = tgt;
            name_at(tgt, rname, sizeof(rname), &roff);   // 拿不到就空串, MCP 层回退 objc_stub@
        } else {
            name_at(tgt, rname, sizeof(rname), &roff);
        }

        // 命中判定: 地址相等(裸目标或解析后目标) 或 符号名相等; objc_stub 额外允许
        // "sym$..." 前缀(现代 objc_msgSend$selector 降级 stub)。
        int addr_match = (query_addr && (resolved == query_addr || tgt == query_addr));
        int name_match = 0;
        if (sym_deunder[0] && rname[0]) {
            if (strcmp(rname, sym_deunder) == 0) name_match = 1;
            else if (strcmp(kind, "call_objc_stub") == 0) {
                size_t L = strlen(sym_deunder);
                if (strncmp(rname, sym_deunder, L) == 0 && rname[L] == '$') name_match = 1;
            }
        }
        if (!addr_match && !name_match) continue;

        if (found >= max_results) { scan.result_limit_reached = 1; break; }
        AnalysisXref *r = &out[found++];
        r->call_site = insn->address;
        r->target = tgt;
        r->resolved_target = resolved;
        strncpy(r->kind, kind, sizeof(r->kind) - 1); r->kind[sizeof(r->kind) - 1] = '\0';
        strncpy(r->resolved_name, rname, sizeof(r->resolved_name) - 1);
        r->resolved_name[sizeof(r->resolved_name) - 1] = '\0';
        // from_func: dladdr 符号优先, 否则 LC_FUNCTION_STARTS 归属到 sub_<runtime>, 都无则留空。
        attribute_call_site(fc, slide, r);
        snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
    }

    cs_free(insn, 1);
    cs_free(sinsn, 1);
    cs_close(&h);
    cs_close(&hs);
    free(snap);
    scan.scanned_insns = scanned;
    if (out_scan) *out_scan = scan;
    return found;
}

// ============================================================
// 字符串引用 (string ref) —— tier-2A
// ============================================================

// arm64_reg → 0..30 索引(仅 X0..X30); 其余(W/SP/XZR)返回 -1 不跟踪。
static int xreg_idx(arm64_reg r) {
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return (int)(r - ARM64_REG_X0);
    if (r == ARM64_REG_FP) return 29;   // X29
    if (r == ARM64_REG_LR) return 30;   // X30
    return -1;
}

// 一段范围表
typedef struct { uint64_t lo, hi; const char *label; } SecRange;

static const char *classify_sec(uint64_t addr, const SecRange *secs, int n) {
    for (int i = 0; i < n; i++) if (addr >= secs[i].lo && addr < secs[i].hi) return secs[i].label;
    return NULL;
}

// 安全读一个 C 字符串到 buf(截断)。返回复制的字节数(不含 NUL); 0=不可读/空。
static int read_cstring(uint64_t addr, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return 0;
    buf[0] = '\0';
    uint8_t tmp[256];
    size_t want = (buflen - 1 < sizeof(tmp)) ? buflen - 1 : sizeof(tmp);
    vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)want,
                          (vm_address_t)tmp, &got) != KERN_SUCCESS || got == 0) return 0;
    size_t i = 0;
    for (; i < (size_t)got && tmp[i]; i++) { buf[i] = (char)tmp[i]; }
    buf[i] = '\0';
    return (int)i;
}

// 某已加载镜像头的 slide(遍历 dyld 表按头指针匹配)。
static intptr_t slide_for_header(const struct mach_header_64 *mh) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++)
        if ((const struct mach_header_64 *)_dyld_get_image_header(i) == mh)
            return _dyld_get_image_vmaddr_slide(i);
    return 0;
}

// 跨镜像判定 addr 是否落在「某镜像的字符串 section」。用于间接引用: 运行时 selref 已被
// 定到 SEL(常在别的镜像/共享缓存), 目标字符串不在被扫镜像内。命中回填 label/vmaddr 返回 1。
static int string_sec_global(uint64_t addr, char *out_label, size_t len, uint64_t *out_vmaddr) {
    Dl_info info;
    if (!dladdr((void *)(uintptr_t)addr, &info) || !info.dli_fbase) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)info.dli_fbase;
    if (mh->magic != MH_MAGIC_64) return 0;
    intptr_t sl = slide_for_header(mh);
    static const char *SS[][2] = {
        {"__TEXT", "__cstring"}, {"__TEXT", "__objc_methname"},
        {"__TEXT", "__objc_classname"}, {"__TEXT", "__objc_methtype"},
    };
    for (int i = 0; i < 4; i++) {
        uint64_t lo, hi;
        if (xref_sect_range(mh, sl, SS[i][0], SS[i][1], &lo, &hi) && addr >= lo && addr < hi) {
            snprintf(out_label, len, "%s,%s", SS[i][0], SS[i][1]);
            if (out_vmaddr) *out_vmaddr = addr - (uint64_t)sl;
            return 1;
        }
    }
    return 0;
}

int analysis_find_string_refs(const char *image_query,
                              const char *query_str, uint64_t query_addr,
                              uint64_t scan_offset, uint64_t scan_size,
                              AnalysisStringRef *out, int max_results,
                              char *out_image, size_t image_len,
                              AnalysisScanInfo *out_scan) {
    if (out_scan) memset(out_scan, 0, sizeof(*out_scan));
    if (!out || max_results <= 0) return -1;
    if ((!query_str || !query_str[0]) && query_addr == 0) return -1;

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    AnalysisScanInfo scan;
    int prep = prepare_scan(text_lo, text_hi, scan_offset, scan_size, &scan);
    if (prep != 0) return prep;

    // 字符串 section(存字符本身)。label 用静态串, 免每次调用 strdup 泄漏。
    SecRange strsec[4]; int nstr = 0;
    static const char *SS[][2] = {
        {"__TEXT", "__cstring"}, {"__TEXT", "__objc_methname"},
        {"__TEXT", "__objc_classname"}, {"__TEXT", "__objc_methtype"},
    };
    static const char *SS_LABEL[4] = {
        "__TEXT,__cstring", "__TEXT,__objc_methname",
        "__TEXT,__objc_classname", "__TEXT,__objc_methtype",
    };
    for (int i = 0; i < 4; i++) {
        uint64_t lo, hi;
        if (xref_sect_range(mh, slide, SS[i][0], SS[i][1], &lo, &hi)) {
            strsec[nstr].lo = lo; strsec[nstr].hi = hi; strsec[nstr].label = SS_LABEL[i];
            nstr++;
        }
    }
    if (nstr == 0) { if (out_scan) *out_scan = scan; return 0; }   // 无字符串 section

    // 指针 section(slot 存指向字符串的指针) — 间接引用 ADRP+LDR 用, 白名单防误报
    SecRange ptrsec[16]; int nptr = 0;
    static const char *PS[][2] = {
        {"__DATA", "__objc_selrefs"}, {"__DATA_CONST", "__objc_selrefs"},
        {"__DATA", "__objc_classrefs"}, {"__DATA_CONST", "__objc_classrefs"},
        {"__DATA", "__objc_superrefs"}, {"__DATA_CONST", "__objc_superrefs"},
        {"__DATA", "__got"}, {"__DATA_CONST", "__got"}, {"__DATA_CONST", "__auth_got"},
        {"__DATA", "__la_symbol_ptr"}, {"__DATA", "__cfstring"}, {"__DATA_CONST", "__cfstring"},
    };
    for (int i = 0; i < (int)(sizeof(PS)/sizeof(PS[0])) && nptr < 16; i++) {
        uint64_t lo, hi;
        if (xref_sect_range(mh, slide, PS[i][0], PS[i][1], &lo, &hi)) {
            ptrsec[nptr].lo = lo; ptrsec[nptr].hi = hi; ptrsec[nptr].label = "ptr"; nptr++;
        }
    }

    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);

    csh h = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return -1;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(h);
    if (!insn) { cs_close(&h); return -1; }

    uint64_t warm_lo = scan.scan_start > text_lo + 4096 ? scan.scan_start - 4096 : text_lo;
    scan.warmup_bytes = (uint32_t)(scan.scan_start - warm_lo);
    scan.bytes_requested += scan.warmup_bytes;
    size_t snap_len = 0;
    uint8_t *snap = snapshot_text(warm_lo, scan.scan_end, &snap_len, &scan);
    if (!snap) { cs_free(insn, 1); cs_close(&h); return -5; }
    const uint8_t *code = snap;
    size_t remaining = snap_len;
    uint64_t cur = warm_lo;
    uint64_t scanned = 0;
    int found = 0;

    // 每寄存器缓存最近 ADRP 页; 被写即失效(局部窗口回溯的等价实现)。
    uint64_t reg_page[31]; uint8_t reg_valid[31];
    memset(reg_valid, 0, sizeof(reg_valid));

    while (cs_disasm_iter(h, &code, &remaining, &cur, insn)) {
        scanned++;
        cs_arm64 *a = &insn->detail->arm64;

        if (insn->id == ARM64_INS_ADRP && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            int di = xreg_idx(a->operands[0].reg);
            if (di >= 0) { reg_page[di] = (uint64_t)a->operands[1].imm; reg_valid[di] = 1; }
            continue;   // ADRP 只设缓存, 不作为使用点
        }

        // 恢复候选数据地址: ADD 直接 / LDR 间接
        int hit = 0, indirect = 0;
        uint64_t str_addr = 0;
        if (insn->id == ARM64_INS_ADD && a->op_count >= 3 &&
            a->operands[1].type == ARM64_OP_REG && a->operands[2].type == ARM64_OP_IMM) {
            int bi = xreg_idx(a->operands[1].reg);
            if (bi >= 0 && reg_valid[bi]) {
                str_addr = reg_page[bi] + (uint64_t)a->operands[2].imm;
                if (classify_sec(str_addr, strsec, nstr)) { hit = 1; indirect = 0; }
            }
        } else if (insn->id == ARM64_INS_LDR && a->op_count >= 2 &&
                   a->operands[1].type == ARM64_OP_MEM &&
                   a->operands[1].mem.index == ARM64_REG_INVALID) {
            int bi = xreg_idx(a->operands[1].mem.base);
            if (bi >= 0 && reg_valid[bi]) {
                uint64_t slot = reg_page[bi] + (uint64_t)a->operands[1].mem.disp;
                // 仅认白名单指针 section(selrefs/got/...); 读出指针即为候选, 目标可能跨镜像
                // (运行时 selref 已定到别处的 SEL), 故不在此限定目标 section, 交由下面读串+匹配。
                if (classify_sec(slot, ptrsec, nptr)) {
                    uint64_t raw = 0;
                    if (read_ptr(slot, &raw)) { str_addr = strip_pac(raw); hit = 1; indirect = 1; }
                }
            }
        }

        if (hit) {
            char sbuf[192];
            int slen = read_cstring(str_addr, sbuf, sizeof(sbuf));
            int match = 0;
            if (slen > 0) {
                if (query_addr) match = (str_addr == query_addr);
                else if (query_str && query_str[0]) match = (strstr(sbuf, query_str) != NULL);
            }
            if (match && insn->address >= scan.scan_start) {
                if (found >= max_results) { scan.result_limit_reached = 1; break; }
                AnalysisStringRef *r = &out[found++];
                r->ref_site = insn->address;
                r->string_addr = str_addr;
                r->indirect = indirect;
                strncpy(r->string, sbuf, sizeof(r->string) - 1); r->string[sizeof(r->string) - 1] = '\0';
                // section + vmaddr: 直接引用在被扫镜像内; 间接引用目标可能跨镜像, 走全局判定。
                const char *lbl = NULL; char glbl[32];
                if (!indirect) { lbl = classify_sec(str_addr, strsec, nstr); r->string_vmaddr = str_addr - (uint64_t)slide; }
                else if (string_sec_global(str_addr, glbl, sizeof(glbl), &r->string_vmaddr)) lbl = glbl;
                else { lbl = "(external)"; r->string_vmaddr = 0; }
                strncpy(r->section, lbl ?: "?", sizeof(r->section) - 1); r->section[sizeof(r->section) - 1] = '\0';
                snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
                attribute_addr(fc, slide, insn->address, r->from_func, sizeof(r->from_func),
                               &r->from_offset, &r->from_func_start, &r->from_func_vmaddr);
            }
        }

        // 失效被写寄存器(先用后失效, 支持 add xN,xN,#off 自更新场景)。
        for (uint8_t i = 0; i < a->op_count; i++) {
            if (a->operands[i].type == ARM64_OP_REG && (a->operands[i].access & CS_AC_WRITE)) {
                int wi = xreg_idx(a->operands[i].reg);
                if (wi >= 0) reg_valid[wi] = 0;
            }
        }
    }

    cs_free(insn, 1);
    cs_close(&h);
    free(snap);
    scan.scanned_insns = scanned;
    if (out_scan) *out_scan = scan;
    return found;
}

// ============================================================
// selector 引用 (selector ref) —— tier-2B
// ============================================================

// objc_msgSend 家族(x1 放 selector 的那几个变体) → 规范静态名; 非家族返回 NULL。
static const char *msgsend_canon(const char *nm) {
    if (!nm) return NULL;
    if (strcmp(nm, "objc_msgSend") == 0)       return "objc_msgSend";
    if (strcmp(nm, "objc_msgSendSuper") == 0)  return "objc_msgSendSuper";
    if (strcmp(nm, "objc_msgSendSuper2") == 0) return "objc_msgSendSuper2";
    return NULL;
}

// selector 匹配: 0=精确 1=包含 2=前缀。
static int sel_match(const char *sel, const char *q, int mode) {
    if (!sel[0] || !q || !q[0]) return 0;
    if (mode == 1) return strstr(sel, q) != NULL;
    if (mode == 2) return strncmp(sel, q, strlen(q)) == 0;
    return strcmp(sel, q) == 0;
}

// bl 直接目标 → 符号名(去下划线)。经 import stub 则解运行时 GOT。命中返回 1。
static int resolve_bl_name(csh hstub, cs_insn *sinsn, uint64_t target,
                           uint64_t st_lo, uint64_t st_hi, uint64_t au_lo, uint64_t au_hi,
                           char *buf, size_t len) {
    buf[0] = '\0'; uint64_t off = 0;
    if (in_range(target, st_lo, st_hi) || in_range(target, au_lo, au_hi)) {
        uint64_t slot = 0, raw = 0;
        if (decode_stub_slot(hstub, sinsn, target, &slot) && read_ptr(slot, &raw)) {
            uint64_t p = strip_pac(raw);
            if (name_at(p, buf, len, &off)) return 1;
            if (name_at(raw, buf, len, &off)) return 1;
        }
        return 0;
    }
    return name_at(target, buf, len, &off);
}

// 解析 __objc_stubs 里某 stub 对应的 selector。优先 dladdr 名 "objc_msgSend$sel";
// 拿不到则反汇编 stub 找 selref 加载读串。命中回填 out_sel 返回 1。
static int objc_stub_selector(csh hstub, cs_insn *sinsn, uint64_t stub_addr,
                              uint64_t sr_lo, uint64_t sr_hi,
                              char *out_sel, size_t len, uint64_t *out_slot) {
    out_sel[0] = '\0'; if (out_slot) *out_slot = 0;
    char nm[320]; uint64_t off = 0;
    if (name_at(stub_addr, nm, sizeof(nm), &off)) {
        const char *d = strchr(nm, '$');
        if (d && d[1]) { strncpy(out_sel, d + 1, len - 1); out_sel[len - 1] = '\0'; return 1; }
    }
    // fallback: 反汇编 stub 找 ADRP+LDR selref
    uint8_t buf[48]; vm_size_t got = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)stub_addr, sizeof(buf),
                          (vm_address_t)buf, &got) != KERN_SUCCESS || got < 8) return 0;
    const uint8_t *p = buf; size_t rem = (size_t)got; uint64_t cur = stub_addr;
    int adrp_reg = -1; uint64_t page = 0; int steps = 0;
    while (steps < 6 && cs_disasm_iter(hstub, &p, &rem, &cur, sinsn)) {
        steps++;
        cs_arm64 *a = &sinsn->detail->arm64;
        if (sinsn->id == ARM64_INS_ADRP && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            adrp_reg = xreg_idx(a->operands[0].reg); page = (uint64_t)a->operands[1].imm;
        } else if (sinsn->id == ARM64_INS_LDR && adrp_reg >= 0 && a->op_count >= 2 &&
                   a->operands[1].type == ARM64_OP_MEM &&
                   xreg_idx(a->operands[1].mem.base) == adrp_reg) {
            uint64_t slot = page + (uint64_t)a->operands[1].mem.disp;
            if (in_range(slot, sr_lo, sr_hi)) {
                uint64_t raw = 0;
                if (read_ptr(slot, &raw) && read_cstring(strip_pac(raw), out_sel, len) > 0) {
                    if (out_slot) *out_slot = slot;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// x1 里 selector 的来源状态
typedef struct { int valid; uint64_t slot, load_site, sel_addr; char sel[256]; } SelReg;

int analysis_find_selector_refs(const char *image_query,
                                const char *selector_q, int match_mode,
                                uint64_t scan_offset, uint64_t scan_size,
                                AnalysisSelectorRef *out, int max_results,
                                char *out_image, size_t image_len,
                                AnalysisScanInfo *out_scan) {
    if (out_scan) memset(out_scan, 0, sizeof(*out_scan));
    if (!out || max_results <= 0) return -1;
    if (!selector_q || !selector_q[0]) return -1;

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    AnalysisScanInfo scan;
    int prep = prepare_scan(text_lo, text_hi, scan_offset, scan_size, &scan);
    if (prep != 0) return prep;

    uint64_t st_lo=0, st_hi=0, au_lo=0, au_hi=0, oc_lo=0, oc_hi=0;
    uint64_t sr_lo=0, sr_hi=0, got_lo=0, got_hi=0, agot_lo=0, agot_hi=0;
    xref_sect_range(mh, slide, "__TEXT", "__stubs", &st_lo, &st_hi);
    xref_sect_range(mh, slide, "__TEXT", "__auth_stubs", &au_lo, &au_hi);
    xref_sect_range(mh, slide, "__TEXT", "__objc_stubs", &oc_lo, &oc_hi);
    xref_sect_range(mh, slide, "__DATA", "__objc_selrefs", &sr_lo, &sr_hi);
    if (!sr_lo) xref_sect_range(mh, slide, "__DATA_CONST", "__objc_selrefs", &sr_lo, &sr_hi);
    xref_sect_range(mh, slide, "__DATA", "__got", &got_lo, &got_hi);
    if (!got_lo) xref_sect_range(mh, slide, "__DATA_CONST", "__got", &got_lo, &got_hi);
    xref_sect_range(mh, slide, "__DATA_CONST", "__auth_got", &agot_lo, &agot_hi);

    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);

    csh h = 0, hs = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return -1;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &hs) != CS_ERR_OK) { cs_close(&h); return -1; }
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(hs, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(h), *sinsn = cs_malloc(hs);
    if (!insn || !sinsn) {
        if (insn) cs_free(insn, 1); if (sinsn) cs_free(sinsn, 1);
        cs_close(&h); cs_close(&hs); return -1;
    }

    uint64_t warm_lo = scan.scan_start > text_lo + 4096 ? scan.scan_start - 4096 : text_lo;
    scan.warmup_bytes = (uint32_t)(scan.scan_start - warm_lo);
    scan.bytes_requested += scan.warmup_bytes;
    size_t snap_len = 0;
    uint8_t *snap = snapshot_text(warm_lo, scan.scan_end, &snap_len, &scan);
    if (!snap) {
        cs_free(insn, 1); cs_free(sinsn, 1); cs_close(&h); cs_close(&hs);
        return -5;
    }
    const uint8_t *code = snap;
    size_t remaining = snap_len;
    uint64_t cur = warm_lo;
    uint64_t scanned = 0;
    int found = 0;

    uint64_t reg_page[31]; uint8_t reg_valid[31];       // ADRP 页缓存
    SelReg   sel_state[31];                             // 各寄存器是否持 selector(来自 selref)
    uint8_t  msg_state[31]; const char *msg_name[31];   // 各寄存器是否持 objc_msgSend(来自 GOT)
    memset(reg_valid, 0, sizeof(reg_valid));
    memset(sel_state, 0, sizeof(sel_state));
    memset(msg_state, 0, sizeof(msg_state));

    while (cs_disasm_iter(h, &code, &remaining, &cur, insn)) {
        scanned++;
        cs_arm64 *a = &insn->detail->arm64;

        // ADRP: 设页缓存, 清该寄存器的 selector/msgSend 状态
        if (insn->id == ARM64_INS_ADRP && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG && a->operands[1].type == ARM64_OP_IMM) {
            int di = xreg_idx(a->operands[0].reg);
            if (di >= 0) { reg_page[di] = (uint64_t)a->operands[1].imm; reg_valid[di] = 1;
                           sel_state[di].valid = 0; msg_state[di] = 0; }
            continue;
        }

        // === 阶段1: 用「当前(旧)状态」识别 objc 调用点并记录 ===
        int x1 = 1;   // ARM64_REG_X1 → 索引 1
        int recorded = 0;
        // 路径 B: bl 到 __objc_stubs
        if (insn->id == ARM64_INS_BL && a->op_count >= 1 && a->operands[0].type == ARM64_OP_IMM &&
            in_range((uint64_t)a->operands[0].imm, oc_lo, oc_hi)) {
            uint64_t stubt = (uint64_t)a->operands[0].imm;
            char sel[256]; uint64_t sslot = 0;
            if (objc_stub_selector(hs, sinsn, stubt, sr_lo, sr_hi, sel, sizeof(sel), &sslot) &&
                sel_match(sel, selector_q, match_mode) && insn->address >= scan.scan_start) {
                if (found >= max_results) { scan.result_limit_reached = 1; break; }
                AnalysisSelectorRef *r = &out[found++];
                memset(r, 0, sizeof(*r));
                r->call_site = insn->address;
                r->selector_slot = sslot;
                strncpy(r->selector, sel, sizeof(r->selector) - 1);
                char nm[320]; uint64_t off;
                if (name_at(stubt, nm, sizeof(nm), &off)) snprintf(r->target, sizeof(r->target), "%s", nm);
                else snprintf(r->target, sizeof(r->target), "objc_stub@0x%llx", stubt);
                strncpy(r->target_kind, "objc_stub", sizeof(r->target_kind) - 1);
                strncpy(r->selector_source, "__objc_stubs", sizeof(r->selector_source) - 1);
                attribute_addr(fc, slide, insn->address, r->from_func, sizeof(r->from_func),
                               &r->from_offset, &r->from_func_start, &r->from_func_vmaddr);
                snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
                recorded = 1;
            }
        }
        // 路径 A: (bl/blr) 到 objc_msgSend, x1 持 selector
        else if (sel_state[x1].valid) {
            const char *variant = NULL;
            if (insn->id == ARM64_INS_BL && a->op_count >= 1 && a->operands[0].type == ARM64_OP_IMM) {
                char nm[256];
                if (resolve_bl_name(hs, sinsn, (uint64_t)a->operands[0].imm,
                                    st_lo, st_hi, au_lo, au_hi, nm, sizeof(nm)))
                    variant = msgsend_canon(nm);
            } else if (insn->id == ARM64_INS_BLR && a->op_count >= 1 && a->operands[0].type == ARM64_OP_REG) {
                int ri = xreg_idx(a->operands[0].reg);
                if (ri >= 0 && msg_state[ri]) variant = msg_name[ri];
            }
            if (variant && sel_match(sel_state[x1].sel, selector_q, match_mode) &&
                insn->address >= scan.scan_start) {
                if (found >= max_results) { scan.result_limit_reached = 1; break; }
                AnalysisSelectorRef *r = &out[found++];
                memset(r, 0, sizeof(*r));
                r->call_site = insn->address;
                r->selector_load_site = sel_state[x1].load_site;
                r->selector_slot = sel_state[x1].slot;
                strncpy(r->selector, sel_state[x1].sel, sizeof(r->selector) - 1);
                snprintf(r->target, sizeof(r->target), "_%s", variant);
                strncpy(r->target_kind, "objc_msgsend", sizeof(r->target_kind) - 1);
                strncpy(r->selector_source, "__objc_selrefs", sizeof(r->selector_source) - 1);
                attribute_addr(fc, slide, insn->address, r->from_func, sizeof(r->from_func),
                               &r->from_offset, &r->from_func_start, &r->from_func_vmaddr);
                snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
                recorded = 1;
            }
        }
        (void)recorded;

        // === 阶段1.5: LDR 新状态「预计算」—— 必须在写失效之前读 reg_valid/reg_page,
        //   否则 ldr xN,[xN,#off] 这种 base==dest 会被阶段2 先清掉 base 的 ADRP 页。===
        int new_di = -1, new_is_sel = 0; SelReg ns; const char *new_msg = NULL;
        memset(&ns, 0, sizeof(ns));
        if (insn->id == ARM64_INS_LDR && a->op_count >= 2 &&
            a->operands[0].type == ARM64_OP_REG &&
            a->operands[1].type == ARM64_OP_MEM &&
            a->operands[1].mem.index == ARM64_REG_INVALID) {
            int bi = xreg_idx(a->operands[1].mem.base);
            int di = xreg_idx(a->operands[0].reg);
            if (bi >= 0 && reg_valid[bi] && di >= 0) {
                uint64_t slot = reg_page[bi] + (uint64_t)a->operands[1].mem.disp;
                if (in_range(slot, sr_lo, sr_hi)) {
                    uint64_t raw = 0; char sbuf[256];
                    if (read_ptr(slot, &raw) && read_cstring(strip_pac(raw), sbuf, sizeof(sbuf)) > 0) {
                        new_di = di; new_is_sel = 1;
                        ns.valid = 1; ns.slot = slot; ns.load_site = insn->address; ns.sel_addr = strip_pac(raw);
                        strncpy(ns.sel, sbuf, sizeof(ns.sel) - 1);
                    }
                } else if (in_range(slot, got_lo, got_hi) || in_range(slot, agot_lo, agot_hi)) {
                    uint64_t raw = 0; char nm[256]; uint64_t off; const char *canon = NULL;
                    if (read_ptr(slot, &raw) && name_at(strip_pac(raw), nm, sizeof(nm), &off) &&
                        (canon = msgsend_canon(nm)) != NULL) { new_di = di; new_msg = canon; }
                }
            }
        }

        // === 阶段2: 写失效(先用后失效); 调用后清 caller-saved x0..x18 ===
        for (uint8_t i = 0; i < a->op_count; i++) {
            if (a->operands[i].type == ARM64_OP_REG && (a->operands[i].access & CS_AC_WRITE)) {
                int wi = xreg_idx(a->operands[i].reg);
                if (wi >= 0) { reg_valid[wi] = 0; sel_state[wi].valid = 0; msg_state[wi] = 0; }
            }
        }
        if (insn->id == ARM64_INS_BL || insn->id == ARM64_INS_BLR) {
            for (int i = 0; i <= 18; i++) { sel_state[i].valid = 0; msg_state[i] = 0; }
        }

        // === 阶段3: 应用阶段1.5 预算出的新状态(覆盖阶段2 对该 dest 的失效) ===
        if (new_di >= 0) {
            if (new_is_sel) { sel_state[new_di] = ns; }
            else if (new_msg) { msg_state[new_di] = 1; msg_name[new_di] = new_msg; }
        }
    }

    cs_free(insn, 1); cs_free(sinsn, 1);
    cs_close(&h); cs_close(&hs);
    free(snap);
    scan.scanned_insns = scanned;
    if (out_scan) *out_scan = scan;
    return found;
}

// ============================================================
// 内部函数调用图 (internal call xref) —— tier-3A
// ============================================================

int analysis_find_function_refs(const char *image_query,
                                uint64_t target_addr, int direction,
                                uint64_t scan_offset, uint64_t scan_size,
                                AnalysisFuncRef *out, int max_results,
                                char *out_image, size_t image_len,
                                uint64_t *out_query_start,
                                AnalysisScanInfo *out_scan) {
    if (out_scan) memset(out_scan, 0, sizeof(*out_scan));
    if (out_query_start) *out_query_start = 0;
    if (!out || max_results <= 0 || target_addr == 0) return -1;
    int want_callers = (direction == 0 || direction == 2);
    int want_callees = (direction == 1 || direction == 2);

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    AnalysisScanInfo scan;
    int prep = prepare_scan(text_lo, text_hi, scan_offset, scan_size, &scan);
    if (prep != 0) return prep;

    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);

    // 查询函数: 把 target_addr 归属到某函数入口。qstart 是过滤基准。
    char qname[256]; uint64_t qoff = 0, qstart = 0, qvm = 0;
    attribute_addr(fc, slide, target_addr, qname, sizeof(qname), &qoff, &qstart, &qvm);
    if (qstart == 0) return -3;   // 归属不到函数
    if (out_query_start) *out_query_start = qstart;

    csh h = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h) != CS_ERR_OK) return -1;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(h);
    if (!insn) { cs_close(&h); return -1; }

    size_t snap_len = 0;
    uint8_t *snap = snapshot_text(scan.scan_start, scan.scan_end, &snap_len, &scan);
    if (!snap) { cs_free(insn, 1); cs_close(&h); return -5; }
    const uint8_t *code = snap;
    size_t remaining = snap_len;
    uint64_t cur = scan.scan_start;
    uint64_t scanned = 0;
    int found = 0;

    while (cs_disasm_iter(h, &code, &remaining, &cur, insn)) {
        scanned++;
        if (insn->id != ARM64_INS_BL) continue;

        cs_arm64 *a = &insn->detail->arm64;
        if (a->op_count < 1 || a->operands[0].type != ARM64_OP_IMM) continue;
        uint64_t tgt = (uint64_t)a->operands[0].imm;
        if (!in_range(tgt, text_lo, text_hi)) continue;   // 只认落在 __text 的内部调用

        // 归属主调(call_site)与被调(target)。
        char ff[256]; uint64_t foff = 0, fstart = 0, fvm = 0;
        char tf[256]; uint64_t toff = 0, tstart = 0, tvm = 0;
        attribute_addr(fc, slide, insn->address, ff, sizeof(ff), &foff, &fstart, &fvm);
        attribute_addr(fc, slide, tgt,           tf, sizeof(tf), &toff, &tstart, &tvm);

        int is_caller = (want_callers && tstart == qstart);   // 有人调用了查询函数
        int is_callee = (want_callees && fstart == qstart);   // 查询函数调用了别人
        if (!is_caller && !is_callee) continue;

        // both 模式下一条边可能同时满足(查询函数自调用): 各记一条以标清 relation。
        for (int pass = 0; pass < 2; pass++) {
            int rel_caller = (pass == 0);
            if (rel_caller && !is_caller) continue;
            if (!rel_caller && !is_callee) continue;
            if (found >= max_results) { scan.result_limit_reached = 1; break; }
            AnalysisFuncRef *r = &out[found++];
            memset(r, 0, sizeof(*r));
            strncpy(r->relation, rel_caller ? "caller" : "callee", sizeof(r->relation) - 1);
            r->call_site = insn->address;
            r->target_addr = tgt;
            strncpy(r->from_func, ff, sizeof(r->from_func) - 1);
            r->from_offset = foff; r->from_func_start = fstart; r->from_func_vmaddr = fvm;
            strncpy(r->to_func, tf, sizeof(r->to_func) - 1);
            r->to_offset = toff; r->to_func_start = tstart; r->to_func_vmaddr = tvm;
            snprintf(r->insn_text, sizeof(r->insn_text), "%s %s", insn->mnemonic, insn->op_str);
        }
        if (scan.result_limit_reached) break;
    }

    cs_free(insn, 1);
    cs_close(&h);
    free(snap);
    scan.scanned_insns = scanned;
    if (out_scan) *out_scan = scan;
    return found;
}

// ============================================================
// 函数清单 (function inventory) —— tier-3B
// ============================================================

int analysis_list_functions(const char *image_query, const char *name_query,
                            int offset, int limit,
                            AnalysisFunction *out, int max_out,
                            char *out_image, size_t image_len, int *out_total) {
    if (out_total) *out_total = 0;
    if (!out || max_out <= 0) return -1;
    if (offset < 0) offset = 0;

    intptr_t slide = 0; char imgnm[256] = {0};
    const struct mach_header_64 *mh = xref_select_image(image_query, &slide, imgnm, sizeof(imgnm));
    if (!mh) return -2;
    if (out_image && image_len) { strncpy(out_image, imgnm, image_len - 1); out_image[image_len - 1] = '\0'; }

    uint64_t text_lo = 0, text_hi = 0;
    if (!xref_sect_range(mh, slide, "__TEXT", "__text", &text_lo, &text_hi) &&
        !xref_sect_range(mh, slide, "__TEXT_EXEC", "__text", &text_lo, &text_hi)) return -2;

    FuncStartsCache *fc = func_starts_for(mh, slide, text_hi);
    if (!fc || fc->count == 0) return 0;   // 无 LC_FUNCTION_STARTS

    int total = 0, added = 0;
    for (size_t i = 0; i < fc->count; i++) {
        uint64_t start = fc->arr[i].runtime;
        uint64_t vm    = fc->arr[i].vmaddr;
        uint64_t end   = (i + 1 < fc->count) ? fc->arr[i + 1].runtime : fc->text_hi;

        char nm[256]; uint64_t off = 0;
        int hassym = name_at(start, nm, sizeof(nm), &off) && off == 0;   // 符号须正好落在入口
        char name[256];
        if (hassym) { strncpy(name, nm, sizeof(name) - 1); name[sizeof(name) - 1] = '\0'; }
        else snprintf(name, sizeof(name), "sub_%llx", start);

        if (name_query && name_query[0] && !strstr(name, name_query)) continue;

        if (total >= offset && added < max_out && (limit <= 0 || added < limit)) {
            AnalysisFunction *r = &out[added++];
            r->start = start; r->vmaddr = vm;
            r->size = (end > start) ? (end - start) : 0;
            strncpy(r->name, name, sizeof(r->name) - 1); r->name[sizeof(r->name) - 1] = '\0';
            r->has_symbol = hassym;
        }
        total++;
    }
    if (out_total) *out_total = total;
    return added;
}
