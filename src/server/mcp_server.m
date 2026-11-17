// mcp_server.m — MCP 服务器实现
//
// MCP over JSON-RPC 2.0。方法分发 + 工具执行 + 标准 content 信封。
// 传输层 (HTTP/SSE/会话头) 在 http_server.m 的 handle_mcp 里。

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <setjmp.h>
#import <signal.h>
#import "dh_symtab.h"
#include <dlfcn.h>
#include "mcp_server.h"
#include "analysis.h"
#include "dh_symtab.h"
#include "log_store.h"
#include "dh_log_json.h"
#include "dh_capture.h"
#include "dh_capability.h"
#include "dh_thunk.h"
#include "dh_event.h"
#include "dh_call_context.h"
#include "dh_hook_selftest.h"
#include "dh_health.h"
#include "dh_unwind.h"
#include "dh_vm_map.h"
#include "dh_flow.h"
#include "dh_noise.h"
#include "dh_spoof.h"
#include "dh_files.h"
#include "dump_manager.h"
#include "hook_webkit.h"
#include "../trace/qbdi_trace.h"
#include "../trace/qbdi_live.h"
#include <string.h>
#include <math.h>

#define MCP_SERVER_NAME     "ios-decrypt-helper"
#ifndef DH_VERSION_STR
#define DH_VERSION_STR "0.0.0"   // 兜底; 正常由 Makefile -D 注入(单一真相源)
#endif
#define MCP_SERVER_VERSION  DH_VERSION_STR
#define MCP_DEFAULT_PROTO   "2024-11-05"

// 我方支持的协议版本 (initialize 时若客户端请求其一则原样回应, 否则回默认)
static NSArray<NSString *> *mcp_supported_protocols(void) {
    return @[@"2024-11-05", @"2025-03-26", @"2025-06-18"];
}

// ============================================================
// JSON-RPC 应答构造
// ============================================================
static NSDictionary *rpc_result(id reqId, NSDictionary *result) {
    return @{@"jsonrpc": @"2.0", @"id": reqId ?: [NSNull null], @"result": result ?: @{}};
}

static NSDictionary *rpc_error(id reqId, NSInteger code, NSString *message) {
    return @{@"jsonrpc": @"2.0", @"id": reqId ?: [NSNull null],
             @"error": @{@"code": @(code), @"message": message ?: @"error"}};
}

// tools/call 的标准结果信封: content(文本, JSON 串) + structuredContent(机器可读) + isError。
static NSDictionary *tool_ok(NSDictionary *structured) {
    NSData *jd = [NSJSONSerialization dataWithJSONObject:structured ?: @{}
                                                options:NSJSONWritingPrettyPrinted error:nil];
    NSString *text = jd ? [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding] : @"{}";
    return @{
        @"content": @[@{@"type": @"text", @"text": text ?: @"{}"}],
        @"structuredContent": structured ?: @{},
        @"isError": @NO,
    };
}

static NSDictionary *tool_err(NSString *message) {
    return @{
        @"content": @[@{@"type": @"text", @"text": [NSString stringWithFormat:@"Error: %@", message ?: @"failed"]}],
        @"isError": @YES,
    };
}

// ============================================================
// 工具实现 —— 返回「tools/call 结果信封」(tool_ok / tool_err)
// ============================================================

// hex 编解码统一用 log_store 的 DHHexFromData / DHDataFromHex, 不再各处手写。

static NSString *operand_access_name(uint8_t access) {
    if ((access & 3) == 3) return @"read_write";
    if (access & 1) return @"read";
    if (access & 2) return @"write";
    return @"unknown";
}

static NSDictionary *operand_to_dict(const AnalysisOperand *op) {
    NSMutableDictionary *out = [@{
        @"access": operand_access_name(op->access),
        @"raw_type": @(op->raw_type),
    } mutableCopy];
    if (op->shift[0]) out[@"shift"] = @{ @"type": @(op->shift), @"value": @(op->shift_value) };
    if (op->extender[0]) out[@"extender"] = @(op->extender);

    switch (op->type) {
        case AnalysisOperandRegister:
            out[@"type"] = @"register";
            out[@"register"] = @(op->reg);
            break;
        case AnalysisOperandImmediate:
            out[@"type"] = @"immediate";
            out[@"value"] = [NSString stringWithFormat:@"0x%llx", (uint64_t)op->immediate];
            out[@"signed_value"] = [NSString stringWithFormat:@"%lld", op->immediate];
            break;
        case AnalysisOperandMemory:
            out[@"type"] = @"memory";
            out[@"base"] = op->base[0] ? (id)@(op->base) : (id)[NSNull null];
            out[@"index"] = op->index[0] ? (id)@(op->index) : (id)[NSNull null];
            out[@"displacement"] = [NSString stringWithFormat:@"%lld", op->displacement];
            out[@"displacement_hex"] = [NSString stringWithFormat:@"0x%llx", (uint64_t)op->displacement];
            break;
        case AnalysisOperandFloatingPoint:
            out[@"type"] = @"floating_point";
            out[@"value"] = @(op->fp);
            break;
        default:
            out[@"type"] = @"other";
            break;
    }
    return out;
}

typedef struct {
    uint64_t value;
    uint64_t known_mask;
    uint64_t sequence_start;
    uint8_t width;
    uint8_t parts;
    uint8_t valid;
} MoveWideState;

// ARM64 move-wide 是固定 32 位编码。直接按编码识别，避免 Capstone 把 MOVZ 显示为 MOV 别名。
static BOOL decode_move_wide(const AnalysisInsn *insn, uint8_t *kind, uint8_t *reg,
                             uint8_t *width, uint16_t *imm16, uint8_t *shift) {
    if (insn->size != 4) return NO;
    uint32_t word = (uint32_t)insn->bytes[0] |
                    ((uint32_t)insn->bytes[1] << 8) |
                    ((uint32_t)insn->bytes[2] << 16) |
                    ((uint32_t)insn->bytes[3] << 24);
    if ((word & 0x1f800000U) != 0x12800000U) return NO;
    uint8_t opc = (uint8_t)((word >> 29) & 3);
    if (opc == 1) return NO;
    uint8_t sf = (uint8_t)(word >> 31);
    uint8_t hw = (uint8_t)((word >> 21) & 3);
    if (!sf && hw > 1) return NO;
    *kind = opc; // 0=MOVN, 2=MOVZ, 3=MOVK
    *reg = (uint8_t)(word & 31);
    *width = sf ? 64 : 32;
    *imm16 = (uint16_t)((word >> 5) & 0xffff);
    *shift = (uint8_t)(hw * 16);
    return YES;
}

static int arm64_gpr_index(const char *name) {
    if (!name || !name[0]) return -1;
    if (strcmp(name, "fp") == 0) return 29;
    if (strcmp(name, "lr") == 0) return 30;
    if ((name[0] != 'x' && name[0] != 'w') || name[1] < '0' || name[1] > '9') return -1;
    char *end = NULL;
    long value = strtol(name + 1, &end, 10);
    return end && *end == '\0' && value >= 0 && value <= 30 ? (int)value : -1;
}

static void add_unique_reg(NSMutableArray *array, const char *name) {
    if (!name || !name[0]) return;
    NSString *value = @(name);
    if (![array containsObject:value]) [array addObject:value];
}

static NSArray *insns_to_array(const AnalysisInsn *insns, int count, NSString *arch) {
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:count];
    MoveWideState constants[31];
    memset(constants, 0, sizeof(constants));
    BOOL trackMoveWide = [arch isEqualToString:@"arm64"] || [arch isEqualToString:@"aarch64"];
    for (int i = 0; i < count; i++) {
        const AnalysisInsn *n = &insns[i];
        NSMutableString *bhex = [NSMutableString stringWithCapacity:n->size * 2];
        for (int j = 0; j < n->size; j++) [bhex appendFormat:@"%02x", n->bytes[j]];
        NSMutableArray *operands = [NSMutableArray arrayWithCapacity:n->operand_count];
        NSMutableArray *regsRead = [NSMutableArray array];
        NSMutableArray *regsWritten = [NSMutableArray array];
        NSString *target = nil;
        for (uint8_t oi = 0; oi < n->operand_count; oi++) {
            const AnalysisOperand *op = &n->operands[oi];
            [operands addObject:operand_to_dict(op)];
            if (op->type == AnalysisOperandRegister) {
                if (op->access & 1) add_unique_reg(regsRead, op->reg);
                if (op->access & 2) add_unique_reg(regsWritten, op->reg);
            } else if (op->type == AnalysisOperandMemory) {
                add_unique_reg(regsRead, op->base);
                add_unique_reg(regsRead, op->index);
                if (n->writeback) add_unique_reg(regsWritten, op->base);
            } else if (op->type == AnalysisOperandImmediate && (n->is_jump || n->is_call)) {
                // ARM64 TBZ/TBNZ 的前一个立即数是位编号，最后一个才是跳转地址。
                // B/BL/B.cond/CBZ/CBNZ 只有一个地址立即数；寄存器间接跳转不伪造目标。
                target = [NSString stringWithFormat:@"0x%llx", (uint64_t)op->immediate];
            }
        }

        NSMutableArray *groups = [NSMutableArray array];
        if (n->is_jump) [groups addObject:@"jump"];
        if (n->is_call) [groups addObject:@"call"];
        if (n->is_return) [groups addObject:@"return"];
        NSMutableDictionary *row = [@{
            @"address": [NSString stringWithFormat:@"0x%llx", n->address],
            @"id": @(n->id),
            @"mnemonic": @(n->mnemonic),
            @"op_str": @(n->op_str),
            @"bytes": bhex,
            @"size": @(n->size),
            @"operands": operands,
            @"operands_truncated": n->operands_truncated ? @YES : @NO,
            @"registers_read": regsRead,
            @"registers_written": regsWritten,
            @"groups": groups,
            @"writes_flags": n->writes_flags ? @YES : @NO,
            @"writeback": n->writeback ? @YES : @NO,
        } mutableCopy];
        if (target) row[@"target"] = target;

        uint8_t kind = 0, reg = 0, width = 0, shift = 0;
        uint16_t imm16 = 0;
        BOOL isMoveWide = trackMoveWide && decode_move_wide(n, &kind, &reg, &width, &imm16, &shift) && reg < 31;
        if (isMoveWide) {
            uint64_t widthMask = width == 64 ? UINT64_MAX : UINT32_MAX;
            uint64_t partMask = ((uint64_t)0xffff << shift) & widthMask;
            uint64_t part = ((uint64_t)imm16 << shift) & widthMask;
            MoveWideState *state = &constants[reg];
            if (kind == 0 || kind == 2) {
                state->value = kind == 0 ? (~part & widthMask) : part;
                state->known_mask = widthMask;
                state->sequence_start = n->address;
                state->width = width;
                state->parts = 1;
                state->valid = 1;
            } else {
                if (!state->valid || state->width != width) {
                    memset(state, 0, sizeof(*state));
                    state->sequence_start = n->address;
                    state->width = width;
                    state->valid = 1;
                }
                state->value = (state->value & ~partMask) | part;
                state->known_mask |= partMask;
                if (state->parts < UINT8_MAX) state->parts++;
            }
            char regName[8];
            snprintf(regName, sizeof(regName), "%c%u", width == 64 ? 'x' : 'w', reg);
            row[@"constant_build"] = @{
                @"register": @(regName),
                @"value": [NSString stringWithFormat:width == 64 ? @"0x%016llx" : @"0x%08llx", state->value],
                @"known_mask": [NSString stringWithFormat:width == 64 ? @"0x%016llx" : @"0x%08llx", state->known_mask],
                @"complete": state->known_mask == widthMask ? @YES : @NO,
                @"width": @(width),
                @"sequence_start": [NSString stringWithFormat:@"0x%llx", state->sequence_start],
                @"instruction_count": @(state->parts),
            };
        } else if (trackMoveWide) {
            for (NSString *written in regsWritten) {
                int idx = arm64_gpr_index(written.UTF8String);
                if (idx >= 0) memset(&constants[idx], 0, sizeof(constants[idx]));
            }
        }

        [arr addObject:row];
        // 不跨控制流传播，宁可少报也不把另一条路径的常量拼进来。
        if (n->is_jump || n->is_call || n->is_return) memset(constants, 0, sizeof(constants));
    }
    return arr;
}

// disassemble —— 反汇编一段 hex 字节
static NSDictionary *tool_disassemble(NSDictionary *args) {
    NSString *bytesHex = args[@"bytes"];
    NSString *addrStr  = args[@"address"];
    NSString *arch     = args[@"arch"] ?: @"arm64";
    if (![bytesHex isKindOfClass:NSString.class] || bytesHex.length == 0)
        return tool_err(@"missing 'bytes' (hex string)");

    NSData *code = DHDataFromHex(bytesHex);
    if (code.length == 0) return tool_err(@"'bytes' has no valid hex");

    uint64_t addr = addrStr ? strtoull(addrStr.UTF8String, NULL, 0) : 0;
    AnalysisInsn *insns = calloc(256, sizeof(AnalysisInsn));
    if (!insns) return tool_err(@"out of memory");
    int n = analysis_disassemble(code.bytes, code.length, addr, arch.UTF8String, insns, 256);
    if (n < 0) { free(insns); return tool_err(@"capstone init failed"); }

    BOOL truncated = (n == 256);
    NSArray *instructions = insns_to_array(insns, n, arch);
    free(insns);
    return tool_ok(@{
        @"arch": arch,
        @"count": @(n),
        @"truncated": @(truncated),
        @"instructions": instructions,
    });
}

// analyze_function —— 读进程内存 address..+size 并反汇编
static NSDictionary *tool_analyze_function(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSNumber *sizeNum = args[@"size"];
    NSString *arch    = args[@"arch"] ?: @"arm64";
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    if (![sizeNum isKindOfClass:NSNumber.class]) return tool_err(@"missing 'size'");

    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    size_t size = (size_t)sizeNum.unsignedLongLongValue;
    if (addr == 0 || size == 0) return tool_err(@"'address' and 'size' must be non-zero");

    AnalysisInsn *insns = calloc(512, sizeof(AnalysisInsn));
    if (!insns) return tool_err(@"out of memory");
    int n = analysis_disassemble_at(addr, size, arch.UTF8String, insns, 512);
    if (n == -2) { free(insns); return tool_err([NSString stringWithFormat:@"memory not readable at 0x%llx", addr]); }
    if (n < 0)  { free(insns); return tool_err(@"capstone init failed"); }
    NSArray *instructions = insns_to_array(insns, n, arch);
    free(insns);

    return tool_ok(@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"arch": arch,
        @"count": @(n),
        @"truncated": (n == 512) ? @YES : @NO,
        @"instructions": instructions,
    });
}

// C 回调: 把符号名收集进 NSMutableArray (与 http_server 的 /api/symbols 同路)
static void sym_collect_cb(const char *name, void *ctx) {
    if (name) [(__bridge NSMutableArray *)ctx addObject:@(name)];
}

// list_images —— 列出 symtab 镜像索引清单 (list_imports 的 image_index 从这里来)
// 默认只列有导入符号的镜像(= fishhook 可 rebind 候选; 也是 list_imports 有意义的目标),
// 主程序排最前; 可用 query 按名过滤。
static NSDictionary *tool_list_images(NSDictionary *args) {
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? [args[@"query"] lowercaseString] : nil;
    int n = dh_symtab_image_count();
    NSMutableArray *arr = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        char nm[256] = {0}; int isMain = 0;
        dh_symtab_image_name(i, nm, sizeof(nm), &isMain);
        int imports = dh_symtab_imports(i, NULL, 0, NULL, NULL);   // 只计数
        if (imports <= 0) continue;
        NSString *name = @(nm);
        if (q && [name.lowercaseString rangeOfString:q].location == NSNotFound) continue;
        [arr addObject:@{@"idx": @(i), @"name": name, @"main": isMain ? @YES : @NO, @"imports": @(imports)}];
    }
    [arr sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL am = [a[@"main"] boolValue], bm = [b[@"main"] boolValue];
        if (am != bm) return am ? NSOrderedAscending : NSOrderedDescending;   // 主程序最前
        return [a[@"name"] caseInsensitiveCompare:b[@"name"]];
    }];
    return tool_ok(@{@"count": @(arr.count), @"images": arr});
}

// list_loaded_images —— 完整 dyld 镜像地图，不按 imports 过滤。
static NSDictionary *tool_list_loaded_images(NSDictionary *args) {
    NSString *query = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : nil;
    BOOL includeSystem = ![args[@"include_system"] isKindOfClass:NSNumber.class] ||
                         [args[@"include_system"] boolValue];
    int offset = [args[@"offset"] isKindOfClass:NSNumber.class] ? [args[@"offset"] intValue] : 0;
    int limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] intValue] : 200;
    if (offset < 0) return tool_err(@"offset must be >= 0");
    if (limit <= 0 || limit > 500) limit = 200;

    AnalysisLoadedImage *rows = calloc((size_t)limit, sizeof(AnalysisLoadedImage));
    if (!rows) return tool_err(@"out of memory");
    int total = 0;
    int n = analysis_list_loaded_images(query.length ? query.UTF8String : NULL,
                                        includeSystem ? 1 : 0, offset, limit,
                                        rows, limit, &total);
    if (n < 0) { free(rows); return tool_err(@"failed to enumerate loaded images"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisLoadedImage *r = &rows[i];
        NSMutableArray *ranges = [NSMutableArray array];
        uint64_t executableBytes = 0;
        for (unsigned int ri = 0; ri < r->executable_range_count; ri++) {
            uint64_t lo = r->executable_ranges[ri].start, hi = r->executable_ranges[ri].end;
            executableBytes += hi - lo;
            [ranges addObject:@{@"segment": @(r->executable_ranges[ri].segment),
                @"start": [NSString stringWithFormat:@"0x%llx", lo],
                @"end": [NSString stringWithFormat:@"0x%llx", hi]}];
        }
        [arr addObject:@{
            @"dyld_index": @(r->dyld_index),
            @"name": @(r->name),
            @"path": @(r->path),
            @"scope": @(r->scope),
            @"main": r->is_main ? @YES : @NO,
            @"uuid": r->uuid[0] ? (id)@(r->uuid) : (id)[NSNull null],
            @"load_address": [NSString stringWithFormat:@"0x%llx", r->load_address],
            @"slide": [NSString stringWithFormat:@"%lld", r->slide],
            @"text_start": r->text_start ? (id)[NSString stringWithFormat:@"0x%llx", r->text_start] : (id)[NSNull null],
            @"text_end": r->text_end ? (id)[NSString stringWithFormat:@"0x%llx", r->text_end] : (id)[NSNull null],
            @"text_size": @(r->text_end > r->text_start ? r->text_end - r->text_start : 0),
            @"text_bounds_kind": @"executable-envelope",
            @"executable_ranges": ranges,
            @"executable_ranges_complete": @(!r->executable_ranges_truncated),
            @"executable_bytes": @(executableBytes),
            @"filetype": @(r->filetype),
            @"encrypted": r->cryptid ? @YES : @NO,
            @"cryptid": @(r->cryptid),
            @"cryptsize": @(r->cryptsize),
        }];
    }
    free(rows);
    return tool_ok(@{
        @"total": @(total), @"offset": @(offset), @"shown": @(n),
        @"include_system": includeSystem ? @YES : @NO, @"images": arr,
    });
}

// list_imports —— 真正遍历某镜像的导入符号
static NSDictionary *tool_list_imports(NSDictionary *args) {
    NSNumber *idxNum = args[@"image_index"];
    if (![idxNum isKindOfClass:NSNumber.class]) return tool_err(@"missing 'image_index'");
    int idx = idxNum.intValue;
    int total_images = dh_symtab_image_count();
    if (idx < 0 || idx >= total_images)
        return tool_err([NSString stringWithFormat:@"image_index out of range (0..%d)", total_images - 1]);

    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : nil;
    int limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] intValue] : 500;
    if (limit <= 0 || limit > 5000) limit = 500;

    char nm[256] = {0}; int isMain = 0;
    dh_symtab_image_name(idx, nm, sizeof(nm), &isMain);

    NSMutableArray *syms = [NSMutableArray array];
    const char *qc = (q.length ? q.UTF8String : NULL);
    int total = dh_symtab_imports(idx, qc, limit, sym_collect_cb, (__bridge void *)syms);

    return tool_ok(@{
        @"image_index": @(idx),
        @"image": @(nm),
        @"main": isMain ? @YES : @NO,
        @"total": @(total),
        @"shown": @(syms.count),
        @"symbols": syms,
    });
}

// disassemble_function —— 中间地址先归一到包含函数入口；无 FUNCTION_STARTS 才退回 ret 启发式。
static NSDictionary *tool_disassemble_function(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSString *arch    = args[@"arch"] ?: @"arm64";
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    if (addr == 0) return tool_err(@"'address' must be non-zero");
    size_t maxBytes = [args[@"max_bytes"] isKindOfClass:NSNumber.class] ? (size_t)[args[@"max_bytes"] unsignedLongLongValue] : 4096;
    if (maxBytes == 0) maxBytes = 4096;
    if (maxBytes > 65536) maxBytes = 65536;

    NSNumber *pageOffsetN = [args[@"byte_offset"] isKindOfClass:NSNumber.class] ? args[@"byte_offset"] : nil;
    if (pageOffsetN && pageOffsetN.longLongValue < 0) return tool_err(@"byte_offset must be non-negative");
    uint64_t pageOffset = pageOffsetN ? pageOffsetN.unsignedLongLongValue : 0;
    unsigned int alignment = [arch isEqualToString:@"thumb"] ? 2 : 4;
    if (pageOffset % alignment) return tool_err(@"byte_offset must align to the instruction size");

    AnalysisInsn *insns = calloc(1024, sizeof(AnalysisInsn));
    if (!insns) return tool_err(@"out of memory");
    AnalysisAddressInfo info;
    BOOL haveFunction = analysis_address_info(addr, &info) == 0 && info.has_function &&
                        info.function_end > info.function_start;
    if (pageOffset && !haveFunction) { free(insns); return tool_err(@"byte_offset requires a known function boundary"); }
    if (haveFunction && pageOffset >= info.function_end - info.function_start) {
        free(insns); return tool_err(@"byte_offset is outside the resolved function");
    }
    uint64_t functionStart = haveFunction ? info.function_start : addr;
    uint64_t readStart = functionStart + pageOffset;
    size_t readSize = maxBytes;
    if (haveFunction && info.function_end - readStart < readSize)
        readSize = (size_t)(info.function_end - readStart);

    int n = haveFunction
        ? analysis_disassemble_at(readStart, readSize, arch.UTF8String, insns, 1024)
        : analysis_disassemble_func(readStart, readSize, arch.UTF8String, insns, 1024);
    if (n == -2) { free(insns); return tool_err([NSString stringWithFormat:@"memory not readable at 0x%llx", addr]); }
    if (n < 0)  { free(insns); return tool_err(@"capstone init failed"); }
    BOOL endsWithRet = (n > 0 && strcmp(insns[n-1].mnemonic, "ret") == 0);
    uint64_t decodedEnd = n > 0 ? insns[n - 1].address + insns[n - 1].size : readStart;
    BOOL truncated = haveFunction ? decodedEnd < info.function_end : (!endsWithRet && readSize == maxBytes);
    NSArray *instructions = insns_to_array(insns, n, arch);
    free(insns);
    NSMutableDictionary *result = [@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"requested_address": [NSString stringWithFormat:@"0x%llx", addr],
        @"resolved_start": [NSString stringWithFormat:@"0x%llx", functionStart],
        @"requested_offset": @(addr - functionStart),
        @"decode_start": [NSString stringWithFormat:@"0x%llx", readStart],
        @"byte_offset": @(pageOffset),
        @"instruction_limit": @1024,
        @"next_byte_offset": truncated && haveFunction ? @(decodedEnd - functionStart) : (id)[NSNull null],
        @"arch": arch,
        @"count": @(n),
        @"ends_with_ret": @(endsWithRet),
        @"boundary_source": haveFunction ? @"lc_function_starts" : @"ret_heuristic",
        // 下一 FUNCTION_STARTS 是可靠上界，但可能包含尾部对齐填充，不宣称是精确 CFG 结束点。
        @"boundary_confidence": haveFunction ? @"medium" : @"low",
        @"boundary_complete": haveFunction ? @(decodedEnd >= info.function_end) : @(endsWithRet),
        @"truncated": @(truncated),
        @"next_address": truncated ? (id)[NSString stringWithFormat:@"0x%llx", decodedEnd] : (id)[NSNull null],
        @"instructions": instructions,
    } mutableCopy];
    if (haveFunction) {
        result[@"resolved_end"] = [NSString stringWithFormat:@"0x%llx", info.function_end];
        result[@"function_vmaddr"] = [NSString stringWithFormat:@"0x%llx", info.function_vmaddr];
        result[@"function_size"] = @(info.function_end - info.function_start);
        result[@"symbol"] = info.symbol[0] ? (id)@(info.symbol) : (id)[NSNull null];
        result[@"symbol_source"] = @(info.symbol_source);
    }
    return tool_ok(result);
}

// resolve_symbol —— 符号名 -> 运行时地址
static NSDictionary *tool_resolve_symbol(NSDictionary *args) {
    NSString *symbol = [args[@"symbol"] isKindOfClass:NSString.class] ? args[@"symbol"] : nil;
    NSString *legacy = [args[@"name"] isKindOfClass:NSString.class] ? args[@"name"] : nil;
    if (symbol.length && legacy.length && ![symbol isEqualToString:legacy])
        return tool_err(@"'symbol' and deprecated 'name' disagree");
    NSString *name = symbol.length ? symbol : legacy;
    if (name.length == 0) return tool_err(@"missing 'symbol' (deprecated alias: 'name')");
    uint64_t addr = 0; char img[256] = {0};
    if (analysis_resolve_symbol(name.UTF8String, &addr, img, sizeof(img)) != 0)
        return tool_err([NSString stringWithFormat:@"symbol not found: %@", name]);
    return tool_ok(@{
        @"name": name,
        @"symbol": name,
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"image": @(img),
    });
}

static NSDictionary *tool_memory_mapping(NSDictionary *args) {
    id value=args[@"address"];if(![value isKindOfClass:NSString.class])return tool_err(@"address must be a hexadecimal string");
    const char *text=[value UTF8String];if(!text)return tool_err(@"address must be UTF8");size_t length=strlen(text);
    if(length<3 || length>18 || [value length]!=length || strncmp(text,"0x",2))return tool_err(@"address must be a 0x-prefixed 64-bit hexadecimal string");
    uint64_t address=0;for(size_t i=2;i<length;i++){char c=text[i];unsigned digit=c>='0' && c<='9'?c-'0':c>='a' && c<='f'?c-'a'+10:c>='A' && c<='F'?c-'A'+10:16;if(digit>15)return tool_err(@"invalid hexadecimal address");address=(address<<4)|digit;}
    DHVMMapping mapping=dh_vm_mapping(address);NSMutableArray *steps=[NSMutableArray array];
    for(unsigned i=0;i<mapping.count;i++) {DHVMRegion *r=&mapping.steps[i];[steps addObject:@{
        @"queryAddress":[NSString stringWithFormat:@"0x%llx",r->inputAddress],@"start":[NSString stringWithFormat:@"0x%llx",r->start],@"length":[NSString stringWithFormat:@"0x%llx",r->length],
        @"requestedDepth":@(r->requestedDepth),@"depth":@(r->depth),@"isSubmap":@(r->isSubmap!=0),@"protection":@(r->protection),@"maxProtection":@(r->maxProtection),@"kernelError":@(r->kernelError)}];}
    return tool_ok(@{@"processGeneration":DHProcessGeneration(),@"address":value,@"found":@(mapping.found!=0),@"executable":@(dh_vm_executable(&mapping)!=0),@"kernelError":@(mapping.kernelError),@"limitReached":@(mapping.limitReached!=0),@"outsideReturnedRegion":@(mapping.invalidRegion!=0),@"walk":steps,@"maxQueries":@DH_VM_WALK_MAX});
}

// symbolicate —— 地址 -> 镜像 + 包含函数 + 有来源/置信度的符号标签
static NSDictionary *tool_symbolicate(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    AnalysisAddressInfo info;
    if (analysis_address_info(addr, &info) != 0)
        return tool_ok(@{@"address": [NSString stringWithFormat:@"0x%llx", addr], @"found": @NO});
    BOOL found = info.symbol[0] != '\0';
    NSMutableDictionary *result = [@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"normalized_address": [NSString stringWithFormat:@"0x%llx", info.normalized_address],
        @"pointer_normalized": (info.normalized_address != addr) ? @YES : @NO,
        @"address_mapped": info.address_mapped ? @YES : @NO,
        @"found": @(found),
        @"has_symbol": info.has_symbol ? @YES : @NO,
        @"symbol": found ? (id)@(info.symbol) : (id)[NSNull null],
        @"symbol_source": @(info.symbol_source),
        @"confidence": @(info.confidence),
        @"offset": @(info.symbol_offset),
        @"display": found ? (id)[NSString stringWithFormat:@"%s+0x%llx", info.symbol, info.symbol_offset] : (id)[NSNull null],
        @"image": info.image[0] ? (id)@(info.image) : (id)[NSNull null],
    } mutableCopy];
    if (info.has_function) {
        result[@"function_start"] = [NSString stringWithFormat:@"0x%llx", info.function_start];
        result[@"function_end"] = [NSString stringWithFormat:@"0x%llx", info.function_end];
        result[@"function_vmaddr"] = [NSString stringWithFormat:@"0x%llx", info.function_vmaddr];
        result[@"function_offset"] = @(info.function_offset);
        result[@"function_size"] = @(info.function_end - info.function_start);
    }
    return tool_ok(result);
}

// isa -> Class: 只认注册过的类, 绝不解引用不可信指针(避免注入进程崩溃)。
// 试 原值 + 常见 non-pointer isa 掩码(arm64 / arm64e-PAC), 命中类表才算数。
static Class dh_class_from_isa(uint64_t isa) {
    if (isa == 0) return NULL;
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    if (!list) return NULL;
    uint64_t cands[3] = { isa, isa & 0x0000000ffffffff8ULL, isa & 0x00007ffffffffff8ULL };
    Class found = NULL;
    for (int c = 0; c < 3 && !found; c++) {
        Class cand = (__bridge Class)(void *)(uintptr_t)cands[c];
        for (unsigned int i = 0; i < n; i++) {
            if (list[i] == cand) { found = cand; break; }
        }
    }
    free(list);
    return found;
}

// objc_resolve_imp —— selector(+class 名 或 object 地址) -> 当前运行时 IMP。
// 破 ObjC 动态派发死结: setRawT: 静态反汇编只到 objc_msgSend 的 `br x16` 就断,
// 注入进程可直接问 runtime 拿当前 IMP,再喂 disassemble_function 反汇编当前执行入口。
static NSDictionary *tool_objc_resolve_imp(NSDictionary *args) {
    NSString *sel = [args[@"selector"] isKindOfClass:NSString.class] ? args[@"selector"] : nil;
    if (sel.length == 0) return tool_err(@"missing 'selector'");
    NSString *className = [args[@"class"]  isKindOfClass:NSString.class] ? args[@"class"]  : nil;
    NSString *objStr    = [args[@"object"] isKindOfClass:NSString.class] ? args[@"object"] : nil;
    NSString *mtype     = [args[@"method_type"] isKindOfClass:NSString.class] ? args[@"method_type"] : @"instance";
    if (!className && !objStr) return tool_err(@"provide 'class' (name) or 'object' (address)");

    SEL selector = NSSelectorFromString(sel);

    // 1) 定位类
    Class cls = NULL;
    NSString *classSource = nil;
    if (objStr) {
        uint64_t objAddr = strtoull(objStr.UTF8String, NULL, 0);
        uint8_t isaBuf[8] = {0};
        int got = analysis_read_memory(objAddr, 8, isaBuf, sizeof(isaBuf));
        if (got != 8) return tool_err([NSString stringWithFormat:@"object address not readable: 0x%llx", objAddr]);
        uint64_t isa = 0; memcpy(&isa, isaBuf, sizeof(isa));
        cls = dh_class_from_isa(isa);
        if (!cls) return tool_err([NSString stringWithFormat:
            @"0x%llx isa=0x%llx 未解析到已注册类(坏对象/tagged pointer)", objAddr, isa]);
        classSource = [NSString stringWithFormat:@"object 0x%llx", objAddr];
    } else {
        cls = objc_getClass(className.UTF8String);
        if (!cls) return tool_err([NSString stringWithFormat:@"class not found: %@", className]);
        classSource = className;
    }

    // 2) instance/class/auto —— 类方法查元类
    BOOL wantClass = [mtype isEqualToString:@"class"];
    BOOL wantAuto  = [mtype isEqualToString:@"auto"];
    Class lookupCls = wantClass ? object_getClass((id)cls) : cls;
    NSString *resolvedType = wantClass ? @"class" : @"instance";
    Method m = class_getInstanceMethod(lookupCls, selector);
    if (!m && wantAuto) {
        m = class_getInstanceMethod(cls, selector);
        if (m) { resolvedType = @"instance"; lookupCls = cls; }
        else {
            lookupCls = object_getClass((id)cls);
            m = class_getInstanceMethod(lookupCls, selector);
            if (m) resolvedType = @"class";
        }
    }
    if (!m) return tool_ok(@{
        @"selector": sel, @"class": @(class_getName(cls)),
        @"class_source": classSource, @"method_type": resolvedType, @"found": @NO,
    });

    IMP imp = method_getImplementation(m);
    uint64_t rawImp = (uint64_t)(uintptr_t)imp;
    uint64_t normalizedImp = rawImp;
    const char *typeEnc = method_getTypeEncoding(m);

    // 3) 声明类(方法可能继承自父类)
    Class declaring = lookupCls;
    Class sup = class_getSuperclass(declaring);
    while (sup && class_getInstanceMethod(sup, selector) == m) {
        declaring = sup; sup = class_getSuperclass(declaring);
    }

    // 4) 当前 IMP 的符号与归属。先做 PAC 归一化，避免带签名指针被 dladdr 误判。
    char symbuf[512] = {0}, imgbuf[256] = {0}; uint64_t off = 0;
    analysis_symbolicate(rawImp, symbuf, sizeof(symbuf), &off,
                         imgbuf, sizeof(imgbuf), &normalizedImp);
    Dl_info info; memset(&info, 0, sizeof(info));
    NSString *symbol = nil, *image = nil;
    if (dladdr((const void *)(uintptr_t)normalizedImp, &info) && info.dli_fname) {
        image = imgbuf[0] ? @(imgbuf) : @(info.dli_fname);
        if (symbuf[0]) symbol = @(symbuf);
    }

    NSMutableDictionary *out = [@{
        @"selector": sel,
        @"class": @(class_getName(cls)),
        @"class_source": classSource,
        @"method_type": resolvedType,
        @"resolving_class": @(class_getName(declaring)),
        @"imp": [NSString stringWithFormat:@"0x%llx", normalizedImp],
        @"current_imp": [NSString stringWithFormat:@"0x%llx", normalizedImp],
        @"raw_imp": [NSString stringWithFormat:@"0x%llx", rawImp],
        @"pointer_normalized": (normalizedImp != rawImp) ? @YES : @NO,
        @"imp_semantics": @"current_runtime_implementation",
        @"original_imp_known": @NO,
        @"type_encoding": typeEnc ? @(typeEnc) : @"",
        @"found": @YES,
    } mutableCopy];
    if (image)  { out[@"image"] = image; out[@"owner_image"] = image; }
    if (symbol) {
        out[@"symbol"] = symbol;
        out[@"symbol_display"] = [NSString stringWithFormat:@"%@+0x%llx", symbol, off];
    }
    out[@"note"] = @"current_imp may already be swizzled by another plugin; this tool does not claim to recover the pre-swizzle implementation";
    return tool_ok(out);
}

// objc_dump_ivars —— 直接读实例的 ivar 表（含 @encode 类型），用于「属性 getter 全 0 命中」的对象。
// 为什么需要它: 很多 SDK 的 singleton 在内部直接读 ivar 而不走 ObjC getter，
// hook getter 会 0 命中，而逐个 object_inspect 又要求先知道字段名。
// 这里按 class_getInstanceVariable 遍历整个继承链，把 NSData/NSString/NSNumber 反引用成可读值。
static NSDictionary *tool_objc_dump_ivars(NSDictionary *args) {
    NSString *className = [args[@"class"] isKindOfClass:NSString.class] ? args[@"class"] : nil;
    NSString *objStr    = [args[@"object"] isKindOfClass:NSString.class] ? args[@"object"] : nil;
    BOOL useShared      = [args[@"shared"] boolValue];
    NSNumber *maxBytesN = [args[@"max_bytes"] isKindOfClass:NSNumber.class] ? args[@"max_bytes"] : nil;
    NSUInteger maxBytes = maxBytesN ? maxBytesN.unsignedIntegerValue : 128;
    if (maxBytes == 0) maxBytes = 128;
    if (maxBytes > 4096) maxBytes = 4096;

    id target = nil;
    Class cls = Nil;
    NSString *source = nil;
    if (objStr) {
        uint64_t a = strtoull(objStr.UTF8String, NULL, 0);
        if (a < 0x100000000ULL) return tool_err(@"object address looks invalid");
        target = (__bridge id)(void *)(uintptr_t)a;
        cls = object_getClass(target);
        source = [NSString stringWithFormat:@"object 0x%llx", a];
    } else {
        if (!className.length) return tool_err(@"provide 'class' (with shared:true) or 'object' (address)");
        cls = objc_getClass(className.UTF8String);
        if (!cls) return tool_err([NSString stringWithFormat:@"class not found: %@", className]);
        source = className;
        if (useShared) {
            SEL sh = NSSelectorFromString(@"sharedInstance");
            if (![cls respondsToSelector:sh]) return tool_err(@"class does not respond to +sharedInstance; pass object address instead");
            IMP imp = class_getMethodImplementation(object_getClass((id)cls), sh);
            if (!imp) return tool_err(@"+sharedInstance has no IMP");
            id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
            target = fn((id)cls, sh);
            if (!target) return tool_err(@"+sharedInstance returned nil");
            cls = object_getClass(target);
        } else {
            return tool_err(@"pass object (address) or set shared:true to read the +sharedInstance object");
        }
    }

    NSMutableArray *rows = [NSMutableArray array];
    NSUInteger total = 0;
    for (Class c = cls; c && c != [NSObject class]; c = class_getSuperclass(c)) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(c, &n);
        if (!ivars) continue;
        for (unsigned int i = 0; i < n; i++) {
            Ivar iv = ivars[i];
            const char *nm = ivar_getName(iv);
            const char *tp = ivar_getTypeEncoding(iv);
            ptrdiff_t off = ivar_getOffset(iv);
            NSMutableDictionary *row = [NSMutableDictionary dictionary];
            row[@"owner"] = @(class_getName(c));
            row[@"name"] = nm ? @(nm) : @"";
            row[@"type"] = tp ? @(tp) : @"";
            row[@"offset"] = @((long long)off);
            @try {
                // KVC 优先: 能走 getter/ivar 两种路径，且能正确桥接对象。
                id value = nil;
                if (nm) {
                    @try { value = [target valueForKey:@(nm)]; }
                    @catch (__unused NSException *ex) { value = nil; }
                }
                if (value) {
                    NSString *desc = nil;
                    if ([value isKindOfClass:[NSData class]]) {
                        NSData *d = value;
                        NSUInteger take = MIN(d.length, maxBytes);
                        NSData *head = take ? [d subdataWithRange:NSMakeRange(0, take)] : [NSData data];
                        desc = [NSString stringWithFormat:@"NSData(%lu) %@%@", (unsigned long)d.length,
                                DHHexFromData(head), d.length > take ? @"…" : @""];
                    } else if ([value isKindOfClass:[NSString class]]) {
                        NSString *s = value;
                        desc = [NSString stringWithFormat:@"NSString(%lu) %@", (unsigned long)s.length,
                                s.length > maxBytes ? [[s substringToIndex:maxBytes] stringByAppendingString:@"…"] : s];
                    } else if ([value isKindOfClass:[NSNumber class]] || [value isKindOfClass:[NSNull class]]) {
                        desc = [value description];
                    } else if ([value isKindOfClass:[NSArray class]] || [value isKindOfClass:[NSDictionary class]]) {
                        NSString *s = [value description];
                        desc = s.length > maxBytes ? [[s substringToIndex:maxBytes] stringByAppendingString:@"…"] : s;
                    } else {
                        desc = [NSString stringWithFormat:@"<%@ %p>", NSStringFromClass([value class]), (void *)value];
                    }
                    if (desc) row[@"value"] = desc;
                }
                // 即使 KVC 拿到 nil，也把原始指针/标量读出来，避免「字段存在但看不到」。
                uint8_t buf[8] = {0};
                if (analysis_read_memory((uint64_t)(uintptr_t)target + (uint64_t)off, 8, buf, sizeof(buf)) == 8) {
                    uint64_t raw = 0; memcpy(&raw, buf, sizeof(raw));
                    row[@"raw_u64"] = [NSString stringWithFormat:@"0x%llx", raw];
                }
            } @catch (__unused NSException *ex) {
                row[@"error"] = @"read failed";
            }
            [rows addObject:row];
            total++;
        }
        free(ivars);
    }
    return tool_ok(@{
        @"class": @(class_getName(cls)),
        @"object": [NSString stringWithFormat:@"0x%llx", (unsigned long long)(uintptr_t)target],
        @"source": source,
        @"count": @(total),
        @"ivars": rows,
        @"note": @"reads the ivar table directly (works when the SDK bypasses ObjC getters); values shown via KVC when available, raw_u64 always present",
    });
}
// objc_export_data —— 把对象上某个 NSData/NSString ivar 原样落盘到沙盒 Documents，
// 供 scp 拉出来做离线分析（密钥表、pwdTable、内嵌二进制这类几十 KB 的载荷，
// 用 read_memory 分块读既慢又容易漏，落盘一次最省）。
static NSDictionary *tool_objc_export_data(NSDictionary *args) {
    NSString *className = [args[@"class"] isKindOfClass:NSString.class] ? args[@"class"] : nil;
    NSString *objStr    = [args[@"object"] isKindOfClass:NSString.class] ? args[@"object"] : nil;
    NSString *ivarName  = [args[@"ivar"] isKindOfClass:NSString.class] ? args[@"ivar"] : nil;
    NSString *outName   = [args[@"name"] isKindOfClass:NSString.class] ? args[@"name"] : nil;
    BOOL useShared      = [args[@"shared"] boolValue];
    if (!ivarName.length) return tool_err(@"missing 'ivar'");

    id target = nil;
    Class cls = Nil;
    if (objStr) {
        uint64_t a = strtoull(objStr.UTF8String, NULL, 0);
        if (a < 0x100000000ULL) return tool_err(@"object address looks invalid");
        target = (__bridge id)(void *)(uintptr_t)a;
        cls = object_getClass(target);
    } else {
        if (!className.length) return tool_err(@"provide 'class'+shared:true or 'object'");
        cls = objc_getClass(className.UTF8String);
        if (!cls) return tool_err([NSString stringWithFormat:@"class not found: %@", className]);
        if (!useShared) return tool_err(@"pass object, or set shared:true");
        SEL sh = NSSelectorFromString(@"sharedInstance");
        if (![cls respondsToSelector:sh]) return tool_err(@"no +sharedInstance");
        IMP imp = class_getMethodImplementation(object_getClass((id)cls), sh);
        id (*fn)(id, SEL) = (id (*)(id, SEL))imp;
        target = fn((id)cls, sh);
        if (!target) return tool_err(@"+sharedInstance returned nil");
        cls = object_getClass(target);
    }

    id value = nil;
    @try { value = [target valueForKey:ivarName]; }
    @catch (NSException *ex) { return tool_err([NSString stringWithFormat:@"valueForKey failed: %@", ex.reason]); }
    if (!value) return tool_err([NSString stringWithFormat:@"%@ is nil", ivarName]);

    NSData *bytes = nil;
    if ([value isKindOfClass:[NSData class]]) bytes = value;
    else if ([value isKindOfClass:[NSString class]]) bytes = [(NSString *)value dataUsingEncoding:NSUTF8StringEncoding];
    else return tool_err([NSString stringWithFormat:@"%@ is %@, not NSData/NSString", ivarName, NSStringFromClass([value class])]);

    // lastPathComponent: 挡住 name 里的 ../ 把文件写到 Documents 之外（仍在沙盒内，但没必要给这个口子）。
    NSString *fname = [outName.length ? outName : [ivarName stringByReplacingOccurrencesOfString:@"_" withString:@""] lastPathComponent];
    if (![fname.pathExtension length]) fname = [fname stringByAppendingPathExtension:@"bin"];
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [dir stringByAppendingPathComponent:fname];
    NSError *err = nil;
    if (![bytes writeToFile:path options:NSDataWritingAtomic error:&err])
        return tool_err([NSString stringWithFormat:@"write failed: %@", err.localizedDescription]);

    // 前 64 字节 hex 便于立刻判断内容形态
    NSUInteger headLen = MIN(bytes.length, (NSUInteger)64);
    NSData *head = [bytes subdataWithRange:NSMakeRange(0, headLen)];
    return tool_ok(@{
        @"class": @(class_getName(cls)),
        @"ivar": ivarName,
        @"path": path,
        @"bytes": @(bytes.length),
        @"head_hex": DHHexFromData(head),
        @"note": @"file written inside the app sandbox Documents; pull it with scp/sftp for offline analysis",
    });
}
// objc_call —— 直接调用一个 ObjC 方法并返回结果。这是逆向里最缺的一环:
// 有了它才能把「签名函数」当 oracle, 喂可控输入观察输出, 而不是靠猜输入组合。
// 只支持 NSString 参数 + 对象返回值 (覆盖签名/摘要/编码这类 facade), 不做任意类型编组。
static NSDictionary *tool_objc_call(NSDictionary *args) {
    NSString *className = [args[@"class"] isKindOfClass:NSString.class] ? args[@"class"] : nil;
    NSString *selName   = [args[@"selector"] isKindOfClass:NSString.class] ? args[@"selector"] : nil;
    BOOL isClassMethod  = [args[@"class_method"] boolValue];
    NSArray *argList    = [args[@"args"] isKindOfClass:NSArray.class] ? args[@"args"] : @[];
    NSString *objStr    = [args[@"object"] isKindOfClass:NSString.class] ? args[@"object"] : nil;
    if (!selName.length) return tool_err(@"missing 'selector'");
    if (!className.length && !objStr) return tool_err(@"provide 'class' or 'object'");
    if (argList.count > 6) return tool_err(@"at most 6 arguments supported (marshalling defines 0..6)");

    SEL sel = NSSelectorFromString(selName);
    id receiver = nil;
    if (objStr) {
        uint64_t a = strtoull(objStr.UTF8String, NULL, 0);
        if (a < 0x100000000ULL) return tool_err(@"object address looks invalid");
        receiver = (__bridge id)(void *)(uintptr_t)a;
    } else {
        Class cls = objc_getClass(className.UTF8String);
        if (!cls) return tool_err([NSString stringWithFormat:@"class not found: %@", className]);
        receiver = isClassMethod ? (id)cls : (id)cls;
        if (!isClassMethod) return tool_err(@"instance call needs 'object' (address); set class_method:true for +method");
    }

    // instance 调用: receiver 是实例, object_getClass(实例) == 它的类 → 查实例方法正确。
    // +method 调用: receiver 是 Class, object_getClass(Class) == 元类 → 类方法正是元类上的实例方法。
    // 两个分支表达式相同是巧合而非笔误; 但写成假三元会让人以为是 bug 而改错其中一支, 所以显式分开。
    Class lookupCls = isClassMethod ? object_getClass((id)receiver) : object_getClass(receiver);
    Method m = class_getInstanceMethod(lookupCls, sel);
    if (!m) return tool_err([NSString stringWithFormat:@"selector not found: %@", selName]);
    IMP imp = method_getImplementation(m);
    if (!imp) return tool_err(@"no IMP");

    // 参数编组。默认按 NSString; 特殊形态用字典表示, 解决「签名方法要 int* 出参」这类签名:
    //   {"$intptr": N}  -> 分配一个 int32 初值 N, 传它的地址 (方法里写回的 errCode 能拿到)
    //   null            -> nil
    // 不认识的形态一律退回 description, 保持向后兼容。
    NSMutableArray *keep = [NSMutableArray array];
    int32_t intSlots[8] = {0};
    BOOL intSlotUsed[8] = {NO};
    // 必须是 __unsafe_unretained: int* 出参要传栈上 intSlots[i] 的地址, 那根本不是对象。
    // 用默认的 __strong 时 ARC 在赋值点就会对栈地址调 objc_storeStrong → retain 读 isa → SIGSEGV
    // (实测 rc=139, 崩在赋值语句本身, 走不到方法调用)。
    __unsafe_unretained id argv[8] = {0};
    for (NSUInteger i = 0; i < argList.count; i++) {
        id v = argList[i];
        if ([v isKindOfClass:[NSNull class]]) { argv[i] = nil; continue; }
        if ([v isKindOfClass:[NSDictionary class]] && v[@"$intptr"]) {
            intSlots[i] = (int32_t)[v[@"$intptr"] intValue];
            intSlotUsed[i] = YES;
            argv[i] = (__bridge id)(void *)&intSlots[i];
            continue;
        }
        NSString *s = [v isKindOfClass:[NSString class]] ? v : [v description];
        [keep addObject:s];
        argv[i] = s;
    }

    id result = nil;
    @try {
        switch (argList.count) {
            case 0: result = ((id (*)(id, SEL))imp)(receiver, sel); break;
            case 1: result = ((id (*)(id, SEL, id))imp)(receiver, sel, argv[0]); break;
            case 2: result = ((id (*)(id, SEL, id, id))imp)(receiver, sel, argv[0], argv[1]); break;
            case 3: result = ((id (*)(id, SEL, id, id, id))imp)(receiver, sel, argv[0], argv[1], argv[2]); break;
            case 4: result = ((id (*)(id, SEL, id, id, id, id))imp)(receiver, sel, argv[0], argv[1], argv[2], argv[3]); break;
            case 5: result = ((id (*)(id, SEL, id, id, id, id, id))imp)(receiver, sel, argv[0], argv[1], argv[2], argv[3], argv[4]); break;
            case 6: result = ((id (*)(id, SEL, id, id, id, id, id, id))imp)(receiver, sel, argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]); break;
            default: return tool_err(@"argument count not supported");
        }
    } @catch (NSException *ex) {
        return tool_err([NSString stringWithFormat:@"target raised %@: %@", ex.name, ex.reason]);
    }

    NSMutableDictionary *out = [@{
        @"class": className ?: @"(object)",
        @"selector": selName,
        @"class_method": isClassMethod ? @YES : @NO,
        @"arg_count": @(argList.count),
        @"returned_nil": result ? @NO : @YES,
    } mutableCopy];
    if (result) {
        out[@"return_class"] = NSStringFromClass([result class]);
        NSString *desc = nil;
        if ([result isKindOfClass:[NSString class]]) desc = result;
        else if ([result isKindOfClass:[NSData class]]) {
            NSData *d = result;
            NSUInteger take = MIN(d.length, (NSUInteger)4096);
            desc = [NSString stringWithFormat:@"NSData(%lu) %@", (unsigned long)d.length,
                    DHHexFromData([d subdataWithRange:NSMakeRange(0, take)])];
        } else desc = [result description];
        if (desc.length > 4096) desc = [[desc substringToIndex:4096] stringByAppendingString:@"…"];
        out[@"result"] = desc ?: @"";
    }
    // 把 int* 出参的最终值回读出来 —— 签名方法常把错误码/长度写在这里。
    NSMutableDictionary *outs = [NSMutableDictionary dictionary];
    for (NSUInteger i = 0; i < argList.count; i++) {
        if (intSlotUsed[i]) outs[[NSString stringWithFormat:@"arg%lu_int", (unsigned long)i]] = @(intSlots[i]);
    }
    if (outs.count) out[@"out_params"] = outs;
    return tool_ok(out);
}
// find_objc_methods —— 基于 ObjC runtime 的实体查询，只列类自身声明的方法。
// ---- 运行时枚举的崩溃兜底 ----
// iOS 16 上对某些 Swift 泛型类调用 class_getName() 会走进
// objc_class::installMangledNameForLazilyNamedClass → Swift demangler 的 C++ 断言 → abort()。
// 这是 C++ 层 fatal, @try/@catch 抓不住, 会直接把宿主 App 打死(实测中国移动 10086 崩溃)。
// 处理: 枚举期间临时接管 SIGABRT, 单个类炸了就跳过它继续, 保证「读运行时信息」永不杀宿主。
// 线程局部: 只有「正在做危险调用」的那个线程才被兜住; 其它线程/其它位置的 abort
// 原样交回原处理器(宿主自己的 BCE_signalExceptHandler 等), 不做全局行为劫持。
static __thread sigjmp_buf gDHObjcAbortJmp;
static __thread volatile sig_atomic_t gDHObjcAbortGuard = 0;
static struct sigaction gDHObjcPrevAbrt;
static BOOL gDHObjcPrevValid = NO;

static void dh_objc_abort_handler(int sig) {
    if (gDHObjcAbortGuard) {
        gDHObjcAbortGuard = 0;
        siglongjmp(gDHObjcAbortJmp, 1);
    }
    // 保护范围之外: 链回原处理器, 保持宿主原有行为。
    if (gDHObjcPrevValid) {
        if (gDHObjcPrevAbrt.sa_flags & SA_SIGINFO) {
            if (gDHObjcPrevAbrt.sa_sigaction) gDHObjcPrevAbrt.sa_sigaction(sig, NULL, NULL);
            return;
        }
        if (gDHObjcPrevAbrt.sa_handler == SIG_IGN) return;
        if (gDHObjcPrevAbrt.sa_handler && gDHObjcPrevAbrt.sa_handler != SIG_DFL) {
            gDHObjcPrevAbrt.sa_handler(sig);
            return;
        }
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

// 安全取类名: 失败(含 abort)返回 NULL 并置 *aborted。
static const char *dh_safe_class_getName(Class cls, int *aborted) {
    if (aborted) *aborted = 0;
    if (!cls) return NULL;
    if (sigsetjmp(gDHObjcAbortJmp, 1) != 0) {
        gDHObjcAbortGuard = 0;
        if (aborted) *aborted = 1;
        return NULL;
    }
    gDHObjcAbortGuard = 1;
    const char *cn = class_getName(cls);
    gDHObjcAbortGuard = 0;
    return cn;
}

static NSDictionary *tool_find_objc_methods(NSDictionary *args) {
    NSString *exactClass = [args[@"class"] isKindOfClass:NSString.class] ? args[@"class"] : nil;
    NSString *classQuery = [args[@"class_query"] isKindOfClass:NSString.class] ? args[@"class_query"] : nil;
    NSString *selector = [args[@"selector"] isKindOfClass:NSString.class] ? args[@"selector"] : nil;
    NSString *imageQuery = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    NSString *impImageQuery = [args[@"imp_image"] isKindOfClass:NSString.class] ? args[@"imp_image"] : nil;
    NSString *match = [args[@"match"] isKindOfClass:NSString.class] ? args[@"match"] : @"contains";
    NSString *methodType = [args[@"method_type"] isKindOfClass:NSString.class] ? args[@"method_type"] : @"both";
    if (!exactClass.length && !classQuery.length && !selector.length &&
        !imageQuery.length && !impImageQuery.length)
        return tool_err(@"provide at least one filter: class, class_query, selector, image, or imp_image");
    if (![@[@"exact", @"contains", @"prefix"] containsObject:match])
        return tool_err(@"match must be exact, contains, or prefix");
    if (![@[@"instance", @"class", @"both"] containsObject:methodType])
        return tool_err(@"method_type must be instance, class, or both");

    int offset = [args[@"offset"] isKindOfClass:NSNumber.class] ? [args[@"offset"] intValue] : 0;
    int limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] intValue] : 200;
    if (offset < 0) return tool_err(@"offset must be >= 0");
    if (limit <= 0 || limit > 500) limit = 200;

    Class singleClass = Nil;
    Class *classes = NULL;
    unsigned int classCount = 0;
    BOOL ownsClasses = NO;
    if (exactClass.length) {
        singleClass = objc_getClass(exactClass.UTF8String);
        if (!singleClass) return tool_ok(@{
            @"total": @0, @"shown": @0, @"offset": @(offset), @"methods": @[],
        });
        classes = &singleClass; classCount = 1;
    } else {
        classes = objc_copyClassList(&classCount);
        ownsClasses = YES;
        if (!classes) return tool_err(@"unable to copy Objective-C class list");
    }

    NSString *classNeedle = classQuery.lowercaseString;
    const char *selectorBytes = selector.UTF8String;
    size_t selectorLength = selectorBytes ? strlen(selectorBytes) : 0;
    int selectorMatch = [match isEqualToString:@"exact"] ? 1 : ([match isEqualToString:@"prefix"] ? 2 : 0);
    NSString *imageNeedle = imageQuery.lowercaseString;
    NSString *impNeedle = impImageQuery.lowercaseString;
    NSMutableArray *rows = [NSMutableArray arrayWithCapacity:(NSUInteger)limit];
    NSInteger total = 0;
    NSUInteger scannedClasses = 0;
    NSInteger skippedLazyNames = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = dh_objc_abort_handler;
    sigemptyset(&sa.sa_mask);
    BOOL abrtHooked = (sigaction(SIGABRT, &sa, &gDHObjcPrevAbrt) == 0);
    gDHObjcPrevValid = abrtHooked;

    for (unsigned int ci = 0; ci < classCount; ci++) {
        Class cls = classes[ci];
        NSString *classImage = nil;
        if (imageNeedle.length) {
            const char *cip = class_getImageName(cls);
            classImage = cip ? @(cip) : @"";
            if ([classImage.lowercaseString rangeOfString:imageNeedle].location == NSNotFound) continue;
        }
        int aborted = 0;
        NSString *className = nil;
        if (classNeedle.length) {
            const char *cn = dh_safe_class_getName(cls, &aborted);
            if (aborted) { skippedLazyNames++; continue; }
            if (!cn) continue;
            className = @(cn);
            if ([className.lowercaseString rangeOfString:classNeedle].location == NSNotFound) continue;
        }
        scannedClasses++;

        for (int kind = 0; kind < 2; kind++) {
            BOOL classMethod = (kind == 1);
            if (classMethod && [methodType isEqualToString:@"instance"]) continue;
            if (!classMethod && [methodType isEqualToString:@"class"]) continue;
            Class holder = classMethod ? object_getClass((id)cls) : cls;
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(holder, &methodCount);
            if (!methods) continue;
            for (unsigned int mi = 0; mi < methodCount; mi++) {
                Method method = methods[mi];
                SEL sel = method_getName(method);
                const char *selBytes = sel ? sel_getName(sel) : "";
                // 先在 C 字符串上筛选；大 App 可能有数百万方法，逐条创建 NSString
                // 会在返回一页结果前产生大量临时对象（快手实测首次全局查询超过 40s）。
                if (selectorLength) {
                    if (selectorMatch == 1 && strcmp(selBytes, selectorBytes) != 0) continue;
                    if (selectorMatch == 2 && strncmp(selBytes, selectorBytes, selectorLength) != 0) continue;
                    if (selectorMatch == 0 && !strstr(selBytes, selectorBytes)) continue;
                }

                // 没有 IMP 镜像过滤时，页外匹配只计数，不做昂贵的符号化。
                if (!impNeedle.length && (total < offset || rows.count >= (NSUInteger)limit)) {
                    total++;
                    continue;
                }

                IMP imp = method_getImplementation(method);
                uint64_t rawImp = (uint64_t)(uintptr_t)imp, normalizedImp = rawImp, symoff = 0;
                char sym[512] = {0}, impImage[256] = {0};
                analysis_symbolicate(rawImp, sym, sizeof(sym), &symoff,
                                     impImage, sizeof(impImage), &normalizedImp);
                NSString *impImageName = impImage[0] ? @(impImage) : @"";
                if (impNeedle.length &&
                    [impImageName.lowercaseString rangeOfString:impNeedle].location == NSNotFound) continue;

                NSInteger idx = total++;
                if (idx < offset || rows.count >= (NSUInteger)limit) continue;
                if (!className) {
                    const char *cn = dh_safe_class_getName(cls, &aborted);
                    if (aborted || !cn) { skippedLazyNames++; continue; }
                    className = @(cn);
                }
                NSString *selName = @(selBytes);
                if (!classImage) {
                    const char *cip = class_getImageName(cls);
                    classImage = cip ? @(cip) : @"";
                }
                const char *enc = method_getTypeEncoding(method);
                NSString *classBase = classImage.lastPathComponent ?: @"";
                BOOL outside = classBase.length && impImageName.length &&
                               ![classBase isEqualToString:impImageName];
                NSMutableDictionary *row = [@{
                    @"class": className,
                    @"selector": selName,
                    @"method_type": classMethod ? @"class" : @"instance",
                    @"type_encoding": enc ? @(enc) : @"",
                    @"current_imp": [NSString stringWithFormat:@"0x%llx", normalizedImp],
                    @"raw_imp": [NSString stringWithFormat:@"0x%llx", rawImp],
                    @"pointer_normalized": normalizedImp != rawImp ? @YES : @NO,
                    @"class_image": classImage.length ? (id)classImage : (id)[NSNull null],
                    @"imp_image": impImageName.length ? (id)impImageName : (id)[NSNull null],
                    @"imp_outside_class_image": outside ? @YES : @NO,
                    @"declared": @YES,
                } mutableCopy];
                if (sym[0]) {
                    row[@"symbol"] = @(sym);
                    row[@"symbol_display"] = [NSString stringWithFormat:@"%s+0x%llx", sym, symoff];
                }
                [rows addObject:row];
            }
            free(methods);
        }
    }
    if (abrtHooked) { sigaction(SIGABRT, &gDHObjcPrevAbrt, NULL); gDHObjcPrevValid = NO; }
    if (ownsClasses) free(classes);
    return tool_ok(@{
        @"total": @(total), @"offset": @(offset), @"shown": @(rows.count),
        @"scanned_classes": @(scannedClasses),
        @"skipped_lazy_names": @(skippedLazyNames),
        @"methods": rows,
        @"note": @"runtime-declared methods only; imp_outside_class_image is an observation, not proof of swizzling",
    });
}

// 经典 hexdump 格式 (地址 / 16 字节 hex / ASCII)
static NSString *format_hexdump(uint64_t base, const uint8_t *buf, int n) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i += 16) {
        [s appendFormat:@"%016llx  ", base + (uint64_t)i];
        NSMutableString *asc = [NSMutableString string];
        for (int j = 0; j < 16; j++) {
            if (i + j < n) {
                uint8_t c = buf[i + j];
                [s appendFormat:@"%02x ", c];
                [asc appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
            } else {
                [s appendString:@"   "];
            }
            if (j == 7) [s appendString:@" "];
        }
        [s appendFormat:@" |%@|\n", asc];
    }
    return s;
}

// read_memory —— 读内存并 hexdump
static NSDictionary *tool_read_memory(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSNumber *sizeNum = args[@"size"];
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    size_t size = [sizeNum isKindOfClass:NSNumber.class] ? (size_t)sizeNum.unsignedLongLongValue : 256;
    if (size == 0) size = 256;

    uint8_t buf[4096];
    int got = analysis_read_memory(addr, size, buf, sizeof(buf));
    if (got == -2) return tool_err([NSString stringWithFormat:@"memory not readable at 0x%llx", addr]);
    if (got < 0)  return tool_err(@"invalid arguments");

    NSString *hex = DHHexFromData([NSData dataWithBytes:buf length:got]);
    return tool_ok(@{
        @"address": [NSString stringWithFormat:@"0x%llx", addr],
        @"size": @(got),
        @"hex": hex,
        @"hexdump": format_hexdump(addr, buf, got),
    });
}

// search_memory —— 在 [address, address+length) 搜索 pattern(hex) 或 string
static NSDictionary *tool_search_memory(NSDictionary *args) {
    NSString *addrStr = args[@"address"];
    NSNumber *lenNum  = args[@"length"];
    if (![addrStr isKindOfClass:NSString.class]) return tool_err(@"missing 'address'");
    if (![lenNum isKindOfClass:NSNumber.class])  return tool_err(@"missing 'length'");
    uint64_t addr = strtoull(addrStr.UTF8String, NULL, 0);
    size_t length = (size_t)lenNum.unsignedLongLongValue;

    NSData *pat = nil;
    if ([args[@"string"] isKindOfClass:NSString.class])
        pat = [args[@"string"] dataUsingEncoding:NSUTF8StringEncoding];
    else if ([args[@"pattern"] isKindOfClass:NSString.class])
        pat = DHDataFromHex(args[@"pattern"]);
    if (pat.length == 0) return tool_err(@"provide 'string' or 'pattern' (hex)");

    uint64_t hits[256];
    int n = analysis_search_memory(addr, length, pat.bytes, pat.length, hits, 256);
    if (n < 0) return tool_err(@"invalid arguments");
    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:n];
    for (int i = 0; i < n; i++) [arr addObject:[NSString stringWithFormat:@"0x%llx", hits[i]]];
    return tool_ok(@{
        @"count": @(n),
        @"truncated": (n == 256) ? @YES : @NO,
        @"hits": arr,
    });
}

// get_macho_info —— 列举 App bundle 内已加载镜像
static NSDictionary *tool_get_macho_info(NSDictionary *args) {
    AnalysisMachoImage imgs[64];
    int n = analysis_list_macho_images(imgs, 64);
    if (n < 0) return tool_err(@"failed to list mach-o images");

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:n];
    int encrypted = 0;
    for (int i = 0; i < n; i++) {
        AnalysisMachoImage *m = &imgs[i];
        if (m->encrypted) encrypted++;
        [arr addObject:@{
            @"name": @(m->name),
            @"kind": @(m->kind),
            @"load_address": [NSString stringWithFormat:@"0x%llx", m->load_address],
            @"encrypted": m->encrypted ? @YES : @NO,
            @"cryptid": @(m->cryptid),
            @"cryptsize": @(m->cryptsize),
        }];
    }
    return tool_ok(@{@"count": @(n), @"encrypted_count": @(encrypted), @"images": arr});
}

static NSString *parse_scan_window(NSDictionary *args, uint64_t *offset, uint64_t *size) {
    NSNumber *off = [args[@"scan_offset"] isKindOfClass:NSNumber.class] ? args[@"scan_offset"] : nil;
    NSNumber *sz = [args[@"scan_size"] isKindOfClass:NSNumber.class] ? args[@"scan_size"] : nil;
    if ((off && off.longLongValue < 0) || (sz && sz.longLongValue < 0))
        return @"scan_offset and scan_size must be >= 0";
    *offset = off ? off.unsignedLongLongValue : 0;
    *size = sz ? sz.unsignedLongLongValue : 0;
    return nil;
}

static NSDictionary *scan_info_dict(const AnalysisScanInfo *s) {
    NSMutableArray *reasons = [NSMutableArray array];
    if (s->has_more) [reasons addObject:@"scan_range_incomplete"];
    if (s->result_limit_reached) [reasons addObject:@"max_results"];
    if (s->scan_size_capped) [reasons addObject:@"scan_size_capped"];
    if (s->insufficient_memory) [reasons addObject:@"insufficient_memory"];
    if (s->unreadable_pages) [reasons addObject:@"unreadable_pages"];
    if (s->partial_pages) [reasons addObject:@"partial_pages"];
    BOOL complete = !s->has_more && !s->result_limit_reached &&
                    s->unreadable_pages == 0 && s->partial_pages == 0;
    return @{
        @"text_start": [NSString stringWithFormat:@"0x%llx", s->text_start],
        @"text_end": [NSString stringWithFormat:@"0x%llx", s->text_end],
        @"text_size": @(s->text_end > s->text_start ? s->text_end - s->text_start : 0),
        @"scan_start": [NSString stringWithFormat:@"0x%llx", s->scan_start],
        @"scan_end": [NSString stringWithFormat:@"0x%llx", s->scan_end],
        @"scan_offset": @(s->scan_offset),
        @"scan_size": @(s->scan_end > s->scan_start ? s->scan_end - s->scan_start : 0),
        @"next_scan_offset": s->has_more ? (id)@(s->next_scan_offset) : (id)[NSNull null],
        @"bytes_requested": @(s->bytes_requested),
        @"bytes_read": @(s->bytes_read),
        @"scanned_insns": @(s->scanned_insns),
        @"unreadable_pages": @(s->unreadable_pages),
        @"partial_pages": @(s->partial_pages),
        @"warmup_bytes": @(s->warmup_bytes),
        @"has_more": s->has_more ? @YES : @NO,
        @"result_limit_reached": s->result_limit_reached ? @YES : @NO,
        @"scan_size_capped": s->scan_size_capped ? @YES : @NO,
        @"insufficient_memory": s->insufficient_memory ? @YES : @NO,
        @"available_memory": @(s->available_memory),
        @"coverage_complete": complete ? @YES : @NO,
        @"incomplete_reasons": reasons,
    };
}

static BOOL scan_is_truncated(const AnalysisScanInfo *s) {
    return s->has_more || s->result_limit_reached || s->unreadable_pages || s->partial_pages;
}

// find_xrefs —— tier-1: 扫某镜像 __text 里所有直接 BL 到目标符号/地址的调用点
static NSDictionary *tool_find_xrefs(NSDictionary *args) {
    NSString *sym     = [args[@"symbol"] isKindOfClass:NSString.class] ? args[@"symbol"] : nil;
    NSString *addrStr = [args[@"address"] isKindOfClass:NSString.class] ? args[@"address"] : nil;
    NSString *image   = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    if (sym.length == 0 && addrStr.length == 0)
        return tool_err(@"need 'symbol' or 'address' to locate the xref target");
    uint64_t scanOffset = 0, scanSize = 0;
    NSString *scanErr = parse_scan_window(args, &scanOffset, &scanSize);
    if (scanErr) return tool_err(scanErr);

    uint64_t targetAddr = addrStr.length ? strtoull(addrStr.UTF8String, NULL, 0) : 0;
    int maxR = [args[@"max_results"] isKindOfClass:NSNumber.class] ? [args[@"max_results"] intValue] : 256;
    if (maxR <= 0 || maxR > 2000) maxR = 256;

    AnalysisXref *rows = calloc((size_t)maxR, sizeof(AnalysisXref));
    if (!rows) return tool_err(@"out of memory");

    uint64_t qaddr = 0; char imgNm[256] = {0}; AnalysisScanInfo scan;
    int n = analysis_find_xrefs(image.length ? image.UTF8String : NULL,
                                sym.length ? sym.UTF8String : NULL, targetAddr,
                                scanOffset, scanSize, rows, maxR,
                                &qaddr, imgNm, sizeof(imgNm), &scan);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }
    if (n == -3) { free(rows); return tool_err([NSString stringWithFormat:@"symbol not resolvable via dlsym: %@ (try passing 'address' instead)", sym]); }
    if (n == -4) { free(rows); return tool_err(@"scan_offset is outside the selected image's __text"); }
    if (n == -5) { free(rows); return tool_err(@"insufficient memory for __text snapshot (host app under memory pressure); retry later or pass a smaller scan_size"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisXref *r = &rows[i];
        NSMutableDictionary *d = [@{
            @"call_site":       [NSString stringWithFormat:@"0x%llx", r->call_site],
            @"target":          [NSString stringWithFormat:@"0x%llx", r->target],
            @"resolved_target": [NSString stringWithFormat:@"0x%llx", r->resolved_target],
            @"kind":            @(r->kind),
            @"instruction":     @(r->insn_text),
        } mutableCopy];
        d[@"resolved_name"] = r->resolved_name[0] ? @(r->resolved_name)
                            : ([@(r->kind) isEqualToString:@"call_objc_stub"]
                               ? [NSString stringWithFormat:@"objc_stub@0x%llx", r->target] : (id)[NSNull null]);
        if (r->from_func[0]) {
            d[@"from_func"]        = [NSString stringWithFormat:@"%s+0x%llx", r->from_func, r->from_offset];
            d[@"from_func_start"]  = [NSString stringWithFormat:@"0x%llx", r->from_func_start];
            d[@"from_func_offset"] = [NSString stringWithFormat:@"0x%llx", r->from_offset];
            if (r->from_func_vmaddr)
                d[@"from_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->from_func_vmaddr];
        } else {
            d[@"from_func"]       = [NSNull null];
            d[@"from_func_start"] = [NSNull null];
        }
        [arr addObject:d];
    }
    free(rows);

    NSMutableDictionary *out = [@{
        @"query":         sym ?: addrStr,
        @"image":         @(imgNm),
        @"scanned_insns": @(scan.scanned_insns),
        @"count":         @(n),
        @"truncated":     scan_is_truncated(&scan) ? @YES : @NO,
        @"scan":          scan_info_dict(&scan),
        @"results":       arr,
    } mutableCopy];
    if (qaddr) out[@"query_address"] = [NSString stringWithFormat:@"0x%llx", qaddr];
    return tool_ok(out);
}

// find_string_refs —— tier-2A: 谁引用了某字符串(ADRP+ADD 直接 / ADRP+LDR 间接)
static NSDictionary *tool_find_string_refs(NSDictionary *args) {
    NSString *str     = [args[@"string"] isKindOfClass:NSString.class] ? args[@"string"] : nil;
    NSString *addrStr = [args[@"address"] isKindOfClass:NSString.class] ? args[@"address"] : nil;
    NSString *image   = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    if (str.length == 0 && addrStr.length == 0)
        return tool_err(@"need 'string' (substring) or 'address' (exact string address)");
    uint64_t scanOffset = 0, scanSize = 0;
    NSString *scanErr = parse_scan_window(args, &scanOffset, &scanSize);
    if (scanErr) return tool_err(scanErr);

    uint64_t queryAddr = addrStr.length ? strtoull(addrStr.UTF8String, NULL, 0) : 0;
    int maxR = [args[@"max_results"] isKindOfClass:NSNumber.class] ? [args[@"max_results"] intValue] : 256;
    if (maxR <= 0 || maxR > 2000) maxR = 256;

    AnalysisStringRef *rows = calloc((size_t)maxR, sizeof(AnalysisStringRef));
    if (!rows) return tool_err(@"out of memory");

    char imgNm[256] = {0}; AnalysisScanInfo scan;
    int n = analysis_find_string_refs(image.length ? image.UTF8String : NULL,
                                      str.length ? str.UTF8String : NULL, queryAddr,
                                      scanOffset, scanSize, rows, maxR,
                                      imgNm, sizeof(imgNm), &scan);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }
    if (n == -4) { free(rows); return tool_err(@"scan_offset is outside the selected image's __text"); }
    if (n == -5) { free(rows); return tool_err(@"insufficient memory for __text snapshot (host app under memory pressure); retry later or pass a smaller scan_size"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisStringRef *r = &rows[i];
        NSMutableDictionary *d = [@{
            @"ref_site":       [NSString stringWithFormat:@"0x%llx", r->ref_site],
            @"string_addr":    [NSString stringWithFormat:@"0x%llx", r->string_addr],
            @"string_vmaddr":  [NSString stringWithFormat:@"0x%llx", r->string_vmaddr],
            @"string":         @(r->string),
            @"section":        @(r->section),
            @"instruction":    @(r->insn_text),
            @"xref_type":      @"string_ref",
            @"indirect":       r->indirect ? @YES : @NO,
        } mutableCopy];
        if (r->from_func[0]) {
            d[@"from_func"]        = [NSString stringWithFormat:@"%s+0x%llx", r->from_func, r->from_offset];
            d[@"from_func_start"]  = [NSString stringWithFormat:@"0x%llx", r->from_func_start];
            d[@"from_func_offset"] = [NSString stringWithFormat:@"0x%llx", r->from_offset];
            if (r->from_func_vmaddr)
                d[@"from_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->from_func_vmaddr];
        } else {
            d[@"from_func"]       = [NSNull null];
            d[@"from_func_start"] = [NSNull null];
        }
        [arr addObject:d];
    }
    free(rows);

    NSMutableDictionary *out = [@{
        @"query":         str ?: addrStr,
        @"image":         @(imgNm),
        @"scanned_insns": @(scan.scanned_insns),
        @"count":         @(n),
        @"truncated":     scan_is_truncated(&scan) ? @YES : @NO,
        @"scan":          scan_info_dict(&scan),
        @"results":       arr,
    } mutableCopy];
    return tool_ok(out);
}

// find_selector_refs —— tier-2B: 谁把某 selector 用在了 objc 调用上
static NSDictionary *tool_find_selector_refs(NSDictionary *args) {
    NSString *sel   = [args[@"selector"] isKindOfClass:NSString.class] ? args[@"selector"] : nil;
    NSString *image = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    NSString *m     = [args[@"match"] isKindOfClass:NSString.class] ? args[@"match"] : @"exact";
    if (sel.length == 0) return tool_err(@"need 'selector'");
    uint64_t scanOffset = 0, scanSize = 0;
    NSString *scanErr = parse_scan_window(args, &scanOffset, &scanSize);
    if (scanErr) return tool_err(scanErr);
    int match_mode = [m isEqualToString:@"contains"] ? 1 : ([m isEqualToString:@"prefix"] ? 2 : 0);
    int maxR = [args[@"max_results"] isKindOfClass:NSNumber.class] ? [args[@"max_results"] intValue] : 256;
    if (maxR <= 0 || maxR > 2000) maxR = 256;

    AnalysisSelectorRef *rows = calloc((size_t)maxR, sizeof(AnalysisSelectorRef));
    if (!rows) return tool_err(@"out of memory");

    char imgNm[256] = {0}; AnalysisScanInfo scan;
    int n = analysis_find_selector_refs(image.length ? image.UTF8String : NULL,
                                        sel.UTF8String, match_mode,
                                        scanOffset, scanSize, rows, maxR,
                                        imgNm, sizeof(imgNm), &scan);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }
    if (n == -4) { free(rows); return tool_err(@"scan_offset is outside the selected image's __text"); }
    if (n == -5) { free(rows); return tool_err(@"insufficient memory for __text snapshot (host app under memory pressure); retry later or pass a smaller scan_size"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisSelectorRef *r = &rows[i];
        NSMutableDictionary *d = [@{
            @"call_site":       [NSString stringWithFormat:@"0x%llx", r->call_site],
            @"selector":        r->selector[0] ? @(r->selector) : (id)[NSNull null],
            @"target":          @(r->target),
            @"target_kind":     @(r->target_kind),
            @"selector_source": @(r->selector_source),
            @"xref_type":       @"selector_ref",
            @"instruction":     @(r->insn_text),
        } mutableCopy];
        d[@"selector_load_site"] = r->selector_load_site ? (id)[NSString stringWithFormat:@"0x%llx", r->selector_load_site] : (id)[NSNull null];
        d[@"selector_slot"]      = r->selector_slot ? (id)[NSString stringWithFormat:@"0x%llx", r->selector_slot] : (id)[NSNull null];
        if (r->from_func[0]) {
            d[@"from_func"]        = [NSString stringWithFormat:@"%s+0x%llx", r->from_func, r->from_offset];
            d[@"from_func_start"]  = [NSString stringWithFormat:@"0x%llx", r->from_func_start];
            d[@"from_func_offset"] = [NSString stringWithFormat:@"0x%llx", r->from_offset];
            if (r->from_func_vmaddr)
                d[@"from_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->from_func_vmaddr];
        } else {
            d[@"from_func"]       = [NSNull null];
            d[@"from_func_start"] = [NSNull null];
        }
        [arr addObject:d];
    }
    free(rows);

    NSMutableDictionary *out = [@{
        @"query":         sel,
        @"match":         m,
        @"image":         @(imgNm),
        @"scanned_insns": @(scan.scanned_insns),
        @"count":         @(n),
        @"truncated":     scan_is_truncated(&scan) ? @YES : @NO,
        @"scan":          scan_info_dict(&scan),
        @"results":       arr,
    } mutableCopy];
    return tool_ok(out);
}

// find_function_refs —— tier-3A: 内部函数调用图 (from_func → to_func)
static NSDictionary *tool_find_function_refs(NSDictionary *args) {
    NSString *addrStr = [args[@"target"] isKindOfClass:NSString.class] ? args[@"target"] : nil;
    NSString *image   = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    NSString *dir     = [args[@"direction"] isKindOfClass:NSString.class] ? args[@"direction"] : @"callers";
    if (addrStr.length == 0) return tool_err(@"need 'target' (function address, e.g. \"0x100012340\")");
    uint64_t scanOffset = 0, scanSize = 0;
    NSString *scanErr = parse_scan_window(args, &scanOffset, &scanSize);
    if (scanErr) return tool_err(scanErr);
    int direction = [dir isEqualToString:@"callees"] ? 1 : ([dir isEqualToString:@"both"] ? 2 : 0);
    uint64_t targetAddr = strtoull(addrStr.UTF8String, NULL, 0);
    int maxR = [args[@"max_results"] isKindOfClass:NSNumber.class] ? [args[@"max_results"] intValue] : 256;
    if (maxR <= 0 || maxR > 2000) maxR = 256;

    AnalysisFuncRef *rows = calloc((size_t)maxR, sizeof(AnalysisFuncRef));
    if (!rows) return tool_err(@"out of memory");

    uint64_t qstart = 0; char imgNm[256] = {0}; AnalysisScanInfo scan;
    int n = analysis_find_function_refs(image.length ? image.UTF8String : NULL,
                                        targetAddr, direction, scanOffset, scanSize,
                                        rows, maxR, imgNm, sizeof(imgNm), &qstart, &scan);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }
    if (n == -3) { free(rows); return tool_err([NSString stringWithFormat:@"target 0x%llx not attributable to a function (no symbol / LC_FUNCTION_STARTS)", targetAddr]); }
    if (n == -4) { free(rows); return tool_err(@"scan_offset is outside the selected image's __text"); }
    if (n == -5) { free(rows); return tool_err(@"insufficient memory for __text snapshot (host app under memory pressure); retry later or pass a smaller scan_size"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisFuncRef *r = &rows[i];
        NSMutableDictionary *d = [@{
            @"xref_type":       @"call_internal",
            @"relation":        @(r->relation),
            @"call_site":       [NSString stringWithFormat:@"0x%llx", r->call_site],
            @"target_addr":     [NSString stringWithFormat:@"0x%llx", r->target_addr],
            @"instruction":     @(r->insn_text),
        } mutableCopy];
        d[@"from_func"] = r->from_func[0] ? (id)[NSString stringWithFormat:@"%s+0x%llx", r->from_func, r->from_offset] : (id)[NSNull null];
        d[@"from_func_start"]  = r->from_func_start ? (id)[NSString stringWithFormat:@"0x%llx", r->from_func_start] : (id)[NSNull null];
        if (r->from_func_vmaddr) d[@"from_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->from_func_vmaddr];
        d[@"to_func"] = r->to_func[0] ? (id)[NSString stringWithFormat:@"%s+0x%llx", r->to_func, r->to_offset] : (id)[NSNull null];
        d[@"to_func_start"]  = r->to_func_start ? (id)[NSString stringWithFormat:@"0x%llx", r->to_func_start] : (id)[NSNull null];
        d[@"to_func_offset"] = [NSString stringWithFormat:@"0x%llx", r->to_offset];
        if (r->to_func_vmaddr) d[@"to_func_vmaddr"] = [NSString stringWithFormat:@"0x%llx", r->to_func_vmaddr];
        [arr addObject:d];
    }
    free(rows);

    NSMutableDictionary *out = [@{
        @"query":         addrStr,
        @"direction":     dir,
        @"image":         @(imgNm),
        @"scanned_insns": @(scan.scanned_insns),
        @"count":         @(n),
        @"truncated":     scan_is_truncated(&scan) ? @YES : @NO,
        @"scan":          scan_info_dict(&scan),
        @"results":       arr,
    } mutableCopy];
    if (qstart) out[@"query_func_start"] = [NSString stringWithFormat:@"0x%llx", qstart];
    return tool_ok(out);
}

// list_functions —— tier-3B: 镜像函数清单 (LC_FUNCTION_STARTS)
static NSDictionary *tool_list_functions(NSDictionary *args) {
    NSString *image = [args[@"image"] isKindOfClass:NSString.class] ? args[@"image"] : nil;
    NSString *query = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : nil;
    int offset = [args[@"offset"] isKindOfClass:NSNumber.class] ? [args[@"offset"] intValue] : 0;
    int limit  = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] intValue] : 200;
    if (limit <= 0 || limit > 2000) limit = 200;

    AnalysisFunction *rows = calloc((size_t)limit, sizeof(AnalysisFunction));
    if (!rows) return tool_err(@"out of memory");

    int total = 0; char imgNm[256] = {0};
    int n = analysis_list_functions(image.length ? image.UTF8String : NULL,
                                    query.length ? query.UTF8String : NULL,
                                    offset, limit, rows, limit, imgNm, sizeof(imgNm), &total);
    if (n == -1) { free(rows); return tool_err(@"invalid arguments"); }
    if (n == -2) { free(rows); return tool_err(@"image or __text section not found"); }

    NSMutableArray *arr = [NSMutableArray arrayWithCapacity:(NSUInteger)n];
    for (int i = 0; i < n; i++) {
        AnalysisFunction *r = &rows[i];
        [arr addObject:@{
            @"name":       @(r->name),
            @"start":      [NSString stringWithFormat:@"0x%llx", r->start],
            @"vmaddr":     [NSString stringWithFormat:@"0x%llx", r->vmaddr],
            @"size":       @(r->size),
            @"has_symbol": r->has_symbol ? @YES : @NO,
        }];
    }
    free(rows);

    return tool_ok(@{
        @"image":    @(imgNm),
        @"total":    @(total),
        @"offset":   @(offset),
        @"shown":    @(n),
        @"functions": arr,
    });
}

// ============================================================
// 取证工具 —— 复用面板同款数据源 (DHLogStore / dh_files / DHDumpManager / dh_capture / dh_health)
// ============================================================

// 分类字符串 -> DHCategory; "all"/未知 -> -1。规范名查分类表, 另收几个别名。
static NSInteger category_from_string(NSString *c) {
    if (![c isKindOfClass:NSString.class] || c.length == 0 || [c isEqualToString:@"all"]) return -1;
    for (NSInteger i = 0; i < dh_log_category_count(); i++)
        if ([c isEqualToString:@(dh_log_category_name(i))]) return i;
    // 别名
    if ([c isEqualToString:@"symmetric"])  return DHCategorySymmetric;
    if ([c isEqualToString:@"asymmetric"]) return DHCategoryAsymmetric;
    if ([c isEqualToString:@"system"])     return DHCategorySystem;
    if ([c isEqualToString:@"network"])    return DHCategoryNetwork;
    if ([c isEqualToString:@"kc"])         return DHCategoryKeychain;
    return -1;
}

// get_stats —— 取证总览: 事件计数 / 捕获开关 / 进程 / 健康 / 落盘量 / 噪声
static NSDictionary *tool_get_stats(NSDictionary *args) {
    DHLogStore *s = [DHLogStore shared];
    NSMutableDictionary *byCat = [NSMutableDictionary dictionary];
    for (NSInteger c = 0; c < dh_log_category_count(); c++)   // 由分类表派生, 不再硬编码
        byCat[@(dh_log_category_name(c))] = @([s countForCategory:(DHCategory)c]);
    NSMutableDictionary *capture = [NSMutableDictionary dictionary];
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++)
        capture[@(dh_capture_sub_name((dh_cap_sub)i))] = @(dh_capture_sub_enabled((dh_cap_sub)i));
    const char *hsum = dh_health_summary();
    return tool_ok(@{
        @"total":      @([s totalCount]),
        @"paused":     @(s.paused),
        @"byCategory": byCat,
        @"capture":    capture,
        @"logBytes":   @([s totalLogBytes]),
        @"pipeline":   [s pipelineStats],
        @"process":    [s processInfo] ?: @{},
        @"noise":      @{@"crypto": @([s noiseCountForBoard:DHNoiseBoardCrypto]),
                         @"sys":    @([s noiseCountForBoard:DHNoiseBoardSys])},
        @"health":     @{
            @"hookFails":     @(dh_health_hook_fail_count()),
            @"persistFailed": dh_health_persist_failed() ? @YES : @NO,
            @"httpFailed":    dh_health_http_failed() ? @YES : @NO,
            @"summary":       (hsum && hsum[0]) ? @(hsum) : @"",
        },
    });
}

// get_capabilities —— 能力握手。上层 AI 首个应调用的工具: 拿到插件版本 / 打包变体 / CPU 架构 /
// 当前阶段(观测 or 改写) / 各档 hook 能力位, 据此决定后续用哪一档 hook, 不对着做不到的能力空转。
static NSDictionary *tool_get_capabilities(NSDictionary *args) {
    (void)args;
    uint32_t bits = dh_capability_bits();
    dh_variant v = dh_variant_current();
    BOOL inlineAvailable = dh_thunk_inline_available() != 0;
    BOOL traceAvailable = DHQBDIAvailable();
    NSMutableArray *dynamicHooks = [NSMutableArray arrayWithArray:@[@"hook_import", @"hook_method"]];
    if (inlineAvailable) [dynamicHooks addObject:@"hook_inline"];
    return tool_ok(@{
        @"pluginVersion":  @MCP_SERVER_VERSION,
        @"processGeneration": DHProcessGeneration(), @"eventSchemaVersion": @2,
        @"flowProtection":@{@"backend":@"owned-bridge stack reconciliation",@"boundaryDetection":@YES,@"transparentVMExceptions":@NO,@"maxGuardsPerThread":@64,@"state":DHFlowState()},
        @"hookABI": @{@"fixedGPRStackForwarding": @YES, @"maxStackBytes": @256, @"maxArguments": @32,
            @"CPostRequiresDeclaration": @YES, @"floatAggregatePost": @NO, @"exceptionUnwind": @NO},
        @"stackUnwind":@{@"backend":dh_unwind_available()?@"system-libunwind":@"unavailable",@"maxFrames":@(DH_STACK_MAX),@"thunkCFI":@YES,@"symbolication":@"deferred",@"scope":@"synchronous-native-thread; metadata gaps and budgets reported"},
        @"liveTrace":@{@"maxSessions":@8,@"maxInstructions":@8192,@"maxPage":@256,@"originalThreadAndStack":@YES,@"budgetAction":@"stop recording; continue original",@"normalReturnRequired":@YES},
        @"variant":        @(dh_variant_id(v)),
        @"variantLabel":   @(dh_variant_label(v)),
        @"arch":           @(dh_cpu_arch()),
        @"phase":          @"observe",   // 一期: 只观测; 二期: override(改写参数/返回值)
        @"capabilities":   @{
            @"hook_import":   (bits & DH_CAPBIT_HOOK_IMPORT)   ? @YES : @NO,  // fishhook GOT 改写
            @"hook_method":   (bits & DH_CAPBIT_HOOK_METHOD)   ? @YES : @NO,  // ObjC swizzle
            @"unpack":        (bits & DH_CAPBIT_UNPACK)        ? @YES : @NO,   // 脱壳
            @"hook_inline":   @(inlineAvailable),
            @"trace_function": @(traceAvailable),
            @"trace_live": @(DHLiveAvailable() && inlineAvailable), @"native_stack_unwind": @(dh_unwind_available()),
        },
        @"capabilityBits": @(bits),
        @"process":        [[DHLogStore shared] processInfo] ?: @{},
        @"dynamicHookTools": dynamicHooks,
        @"backends": @{
            @"inline": inlineAvailable ? @"dobby" : @"unavailable",
            @"trace": traceAvailable ? @"qbdi" : @"unavailable",
        },
        // 标准 crypto hook 全空时的通用排查路径。让 Agent 在第一次握手就拿到这条引导,
        // 而不是只对着 CCCrypt/EVP 空转。
        @"guidance": @{
            @"whenNoCryptoEvents": @[
                @"标准 sym/asym/digest hook 全空、但网络层已有密文时，先 get_capture_coverage 确认 blind spot。",
                @"用 list_images → list_imports 找静态加密库仍会调用的「指针+长度」导入(mlock/memcpy/read/send/getrandom)。",
                @"用 hook_import + capture_memory 在命中瞬间抓缓冲区；只存指针、事后 read_memory 通常已被释放/复用。",
                @"候选 key 必须做「解密 + 回加密逐字节一致」闭环，并多次触发确认 key 生命周期。",
            ],
        },
    });
}

// ===== 动态 hook (一期: record-only, 观测) =====
// 解析可选的 capture_memory 配置: 命中瞬间把「指针参数指向的内存」拷进事件 input。
// ptr_arg/len_arg 是寄存器位置(x0..x8; method hook 里 x0=self, x1=_cmd, x2..=参数)。
// 未提供该字段时 *ptr_arg_out = -1(不开启); 校验失败时返回 NO 并给出错误文本。
static BOOL dh_parse_capture_memory(NSDictionary *args, int *ptr_arg_out, int *len_arg_out,
                                    int *max_bytes_out, NSString **error) {
    *ptr_arg_out = -1; *len_arg_out = -1; *max_bytes_out = 0;
    id raw = args[@"capture_memory"];
    if (!raw) return YES;
    if (![raw isKindOfClass:NSDictionary.class]) {
        if (error) *error = @"capture_memory 必须是对象: {ptr_arg, len_arg, max_bytes}";
        return NO;
    }
    NSDictionary *c = raw;
    for (NSString *key in @[@"ptr_arg", @"len_arg", @"max_bytes"]) {
        id value = c[key];
        if (!value) continue;
        double number = [value isKindOfClass:NSNumber.class] ? [value doubleValue] : NAN;
        double low = [key isEqualToString:@"len_arg"] ? -1 : [key isEqualToString:@"max_bytes"] ? 1 : 0;
        double high = [key isEqualToString:@"max_bytes"] ? DH_THUNK_CAPTURE_MAX : 8;
        if (!isfinite(number) || floor(number) != number || number < low || number > high) {
            if (error) *error = [key stringByAppendingString:@" must be an integer within capture_memory bounds"];
            return NO;
        }
    }
    int ptrArg = c[@"ptr_arg"] ? [c[@"ptr_arg"] intValue] : 0;
    int lenArg = c[@"len_arg"] ? [c[@"len_arg"] intValue] : -1;
    int maxBytes = c[@"max_bytes"] ? [c[@"max_bytes"] intValue] : 256;
    if (ptrArg < 0 || ptrArg > 8 || lenArg < -1 || lenArg > 8 ||
        maxBytes < 1 || maxBytes > DH_THUNK_CAPTURE_MAX) {
        if (error) *error = [NSString stringWithFormat:
            @"capture_memory 参数越界(ptr_arg=%d, len_arg=%d, max_bytes=%d); 要求 ptr_arg 0..8, len_arg -1..8, max_bytes 1..%d",
            ptrArg, lenArg, maxBytes, DH_THUNK_CAPTURE_MAX];
        return NO;
    }
    *ptr_arg_out = ptrArg; *len_arg_out = lenArg; *max_bytes_out = maxBytes;
    return YES;
}

static NSDictionary *dh_capture_echo(int ptrArg, int lenArg, int maxBytes) {
    if (ptrArg < 0) return nil;
    return @{@"ptr_arg": @(ptrArg), @"len_arg": @(lenArg), @"max_bytes": @(maxBytes)};
}

static NSString *dh_capture_phase_note(BOOL after, int ptrArg, int lenArg, int maxBytes) {
    return [NSString stringWithFormat:@" capture_memory: x%d, len_arg=%d, cap=%d bytes; %@",
            ptrArg, lenArg, maxBytes, after
            ? @"入口不读输出缓冲，返回后按入口指针采集到 output。"
            : @"入口命中时采集到 input。"];
}

static BOOL dh_hook_options_from_args(NSDictionary *args, dh_hook_options *o, NSString **error) {
    dh_thunk_options_default(o);
    for (NSString *key in @[@"describe_args", @"capture_return", @"capture_after", @"classMethod"]) {
        id value = args[key];
        if (value && (![value isKindOfClass:NSNumber.class] || ([value doubleValue] != 0 && [value doubleValue] != 1))) {
            *error = [key stringByAppendingString:@" must be a boolean"]; return NO;
        }
    }
    o->describe_args = [args[@"describe_args"] boolValue];
    o->capture_return = [args[@"capture_return"] boolValue];
    o->capture_after = [args[@"capture_after"] boolValue];
    if (args[@"post_abi"] && ![args[@"post_abi"] isEqual:@"fixed-nonvariadic"]) {
        *error = @"post_abi supports only fixed-nonvariadic"; return NO;
    }
    o->fixed_abi = [args[@"post_abi"] isEqual:@"fixed-nonvariadic"];
    if (!dh_parse_capture_memory(args, &o->ptr_arg, &o->len_arg, &o->max_bytes, error)) return NO;
    for (NSString *key in @[@"capture_multi", @"capture_ret_multi"]) {
        id value = args[key];
        if (value && (![value isKindOfClass:NSString.class] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] >= 96)) {
            *error = [key stringByAppendingString:@" must be a string shorter than 96 bytes"]; return NO;
        }
        if (value) strlcpy([key isEqualToString:@"capture_multi"] ? o->capture_multi : o->capture_ret_multi, [value UTF8String], 96);
    }
    if (args[@"abi"]) {
        NSDictionary *abi = args[@"abi"];
        if (![abi isKindOfClass:NSDictionary.class] || ![abi[@"arguments"] isKindOfClass:NSArray.class] ||
            ![abi[@"return"] isKindOfClass:NSString.class] || [abi[@"arguments"] count] > 32) {
            *error = @"abi requires arguments (0..32 fixed types) and return type"; return NO;
        }
        for (NSString *key in @[@"variadic", @"exception_unwind"]) {
            id value = abi[key];
            if (value && (![value isKindOfClass:NSNumber.class] || ([value doubleValue] != 0 && [value doubleValue] != 1))) {
                *error = [key stringByAppendingString:@" must be a boolean"]; return NO;
            }
        }
        if ([abi[@"variadic"] boolValue] || [abi[@"exception_unwind"] boolValue]) {
            *error = @"variadic/exception-unwind ABI is not supported; use opaque entry-only capture"; return NO;
        }
        NSDictionary *types = @{@"pointer": @"^", @"object": @"@", @"u64": @"Q", @"i64": @"q",
            @"u32": @"I", @"i32": @"i", @"u16": @"S", @"i16": @"s", @"u8": @"C", @"i8": @"c", @"bool": @"B", @"void": @"v"};
        NSArray *arguments = abi[@"arguments"];
        for (NSUInteger i = 0; i < arguments.count; i++) {
            NSString *type = [arguments[i] isKindOfClass:NSString.class] ? types[arguments[i]] : nil;
            if (!type || [type isEqualToString:@"v"]) { *error = @"ABI arguments support only fixed GPR scalar/pointer types"; return NO; }
            o->argument_types[i] = [type UTF8String][0];
        }
        NSString *ret = types[abi[@"return"]];
        if (!ret) { *error = @"ABI return supports void or GPR scalar/pointer types"; return NO; }
        o->abi_declared = 1; o->argument_count = (unsigned)arguments.count; o->return_type = ret.UTF8String[0];
    }
    char reason[256] = {0};
    if (dh_thunk_validate_options(o, reason, sizeof(reason))) { *error = @(reason); return NO; }
    return YES;
}

static NSDictionary *dh_install_hook(NSDictionary *args, dh_hook_kind kind, const char *owner,
                                     const char *name, uint64_t address, NSString *label) {
    dh_hook_options options; NSString *error = nil;
    if (!dh_hook_options_from_args(args, &options, &error)) return tool_err(error);
    if (kind == DH_HOOK_METHOD && options.abi_declared) return tool_err(@"method ABI comes from runtime; do not override it with a C declaration");
    char reason[512] = {0};
    int slot = dh_thunk_install_configured(kind, owner, name, address, [args[@"classMethod"] boolValue],
        label.UTF8String, &options, reason, sizeof(reason));
    if (slot <= -10) return tool_err([NSString stringWithFormat:@"symbol already hooked at slot %d; immutable configuration was not changed", -slot - 10]);
    if (slot < 0) return tool_err([NSString stringWithFormat:@"hook install rejected (%d): %s", slot,
        reason[0] ? reason : slot == -5 ? "target already hooked" : slot == -3 ? "method not found" : slot == -2 ? "target/import not found" : "installation unavailable"]);
    NSMutableDictionary *out = [dh_thunk_metadata(slot) mutableCopy];
    out[@"slot"] = @(slot); out[@"enabled"] = @YES;
    out[@"kind"] = kind == DH_HOOK_METHOD ? @"method" : kind == DH_HOOK_INLINE ? @"inline" : @"import";
    out[@"capture_return"] = @(options.capture_return); out[@"capture_after"] = @(options.capture_after);
    out[@"capture_multi"] = @(options.capture_multi); out[@"capture_ret_multi"] = @(options.capture_ret_multi);
    if (options.ptr_arg >= 0) {
        out[@"capture"] = dh_capture_echo(options.ptr_arg, options.len_arg, options.max_bytes);
        out[@"capture_phase"] = options.capture_after ? @"leave" : @"entry";
    }
    out[@"note"] = @"configuration validated before patch publication; v2 events use phase/callId/parentCallId/payload; post supports declared fixed-GPR ABI with bounded stack forwarding, not exception unwinding";
    return tool_ok(out);
}

static NSDictionary *tool_hook_import(NSDictionary *args) {
    NSString *name = args[@"symbol"], *label = args[@"label"];
    if (![name isKindOfClass:NSString.class] || !name.length) return tool_err(@"symbol required");
    if (label && ![label isKindOfClass:NSString.class]) return tool_err(@"label must be a string");
    return dh_install_hook(args, DH_HOOK_IMPORT, NULL, name.UTF8String, 0, label);
}

// hook_inline — 对任意函数装只读内联 hook (Dobby)。复用 thunk 表做入口快照 + 尾调用原函数。
// 目标可以是 module+symbol，也可以是绝对地址；对静态链接/模块内自研函数同样有效。
static BOOL dh_parse_addr_arg(id raw, uint64_t *out) {
    if (!raw) return NO;
    if ([raw isKindOfClass:NSNumber.class]) { *out = [raw unsignedLongLongValue]; return YES; }
    if ([raw isKindOfClass:NSString.class]) {
        NSString *s = [(NSString *)raw stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([s hasPrefix:@"0x"] || [s hasPrefix:@"0X"]) s = [s substringFromIndex:2];
        if (s.length == 0) return NO;
        const char *c = s.UTF8String;
        char *end = NULL;
        unsigned long long v = strtoull(c, &end, 16);
        if (end == c || (end && *end != '\0')) return NO;
        *out = (uint64_t)v;
        return YES;
    }
    return NO;
}

static NSDictionary *tool_hook_inline(NSDictionary *args) {
    NSString *module = args[@"module"], *symbol = args[@"symbol"], *label = args[@"label"];
    for (id value in @[module ?: @"", symbol ?: @"", label ?: @""])
        if (![value isKindOfClass:NSString.class]) return tool_err(@"module/symbol/label must be strings");
    uint64_t address = 0;
    if (args[@"addr"] && !dh_parse_addr_arg(args[@"addr"], &address)) return tool_err(@"invalid address");
    if (!address && !symbol.length) return tool_err(@"symbol or non-zero address required");
    return dh_install_hook(args, DH_HOOK_INLINE, module.UTF8String, symbol.UTF8String, address, label);
}

// trace_function — QBDI 指令级 trace（一次显式函数调用 + 有界指令记录）。
static NSDictionary *tool_trace_function(NSDictionary *args) {
    NSString *module = [args[@"module"] isKindOfClass:NSString.class] ? args[@"module"] : nil;
    NSString *symbol = [args[@"symbol"] isKindOfClass:NSString.class] ? args[@"symbol"] : nil;
    uint64_t addr = 0;
    BOOL hasAddr = (args[@"addr"] != nil);
    if (hasAddr && !dh_parse_addr_arg(args[@"addr"], &addr)) {
        return tool_err(@"addr 必须是数字或十六进制字符串（如 \"0x1004a2b30\"）");
    }
    if (!hasAddr && symbol.length == 0) return tool_err(@"symbol 或 addr 至少提供一个");

    uint64_t argv[8] = {0};
    int argc = 0;
    id rawArgs = args[@"args"];
    if (rawArgs) {
        if (![rawArgs isKindOfClass:NSArray.class]) return tool_err(@"args 必须是数组");
        NSArray *a = rawArgs;
        if (a.count>8) return tool_err(@"trace supports at most eight fixed GPR arguments");
        argc = (int)a.count;
        for (int i = 0; i < argc; i++) {
            if (!dh_parse_addr_arg(a[i], &argv[i])) {
                return tool_err([NSString stringWithFormat:
                    @"args[%d] 必须是数字或十六进制字符串", i]);
            }
        }
    }
    int maxInsns = [args[@"max_insns"] isKindOfClass:NSNumber.class] ? [args[@"max_insns"] intValue] : 256;
    int maxMs = [args[@"max_ms"] isKindOfClass:NSNumber.class] ? [args[@"max_ms"] intValue] : 3000;
    if (maxInsns < 1) maxInsns = 1;
    if (maxInsns > 4096) maxInsns = 4096;
    if (maxMs < 50) maxMs = 50;
    if (maxMs > 10000) maxMs = 10000;

    NSDictionary *res = DHQBDITraceFunctionWithBuffers(module, symbol, addr, argv, argc, maxInsns, maxMs, args[@"buffers"]);
    if (![res[@"ok"] boolValue]) {
        return tool_err(res[@"error"] ?: @"QBDI trace failed");
    }
    return tool_ok(res);
}

// hook_method — 对 ObjC 方法装只读 hook (method_setImplementation swizzle)。同一套 thunk, x0=self x1=_cmd。
static NSDictionary *tool_hook_method(NSDictionary *args) {
    NSString *cls = args[@"class"], *selector = args[@"selector"];
    if (![cls isKindOfClass:NSString.class] || !cls.length) return tool_err(@"class required");
    if (![selector isKindOfClass:NSString.class] || !selector.length) return tool_err(@"selector required");
    return dh_install_hook(args, DH_HOOK_METHOD, cls.UTF8String, selector.UTF8String, 0, nil);
}

// list_hooks — 枚举当前所有动态 hook (含命中次数与启用状态)。
static NSDictionary *tool_list_hooks(NSDictionary *args) {
    (void)args;
    dh_hook_info info[DH_THUNK_COUNT];
    int n = dh_thunk_list(info, DH_THUNK_COUNT);
    NSMutableArray *arr = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        NSMutableDictionary *h = [@{
            @"slot":    @(info[i].slot),
            @"kind":    info[i].kind == DH_HOOK_METHOD ? @"method"
                     : (info[i].kind == DH_HOOK_INLINE ? @"inline" : @"import"),
            @"name":    info[i].name ? @(info[i].name) : @"",
            @"hits":    @(info[i].hits),
            @"enabled": info[i].enabled ? @YES : @NO,
            @"retired": info[i].retired ? @YES : @NO,
            @"capture_return": info[i].capture_return ? @YES : @NO,
            @"capture_after":  info[i].capture_after ? @YES : @NO,
            @"capture_multi":  info[i].capture_multi[0] ? @(info[i].capture_multi) : @"",
            @"capture_ret_multi": info[i].capture_ret_multi[0] ? @(info[i].capture_ret_multi) : @"",
        } mutableCopy];
        if (info[i].kind == DH_HOOK_METHOD) {
            h[@"declared_args"] = @(info[i].method_arg_count);
            h[@"argument_mapping"] = info[i].method_simple_gpr ? @"simple-gpr" : @"unsupported-signature";
            h[@"stack_snapshot_bytes"] = @(info[i].method_stack_bytes);
        }
        NSDictionary *cap = dh_capture_echo(info[i].capture_ptr_arg, info[i].capture_len_arg,
                                            info[i].capture_max_bytes);
        if (cap) h[@"capture"] = cap;
        [h addEntriesFromDictionary:dh_thunk_metadata(info[i].slot)];
        [arr addObject:h];
    }
    return tool_ok(@{@"processGeneration": DHProcessGeneration(), @"count": @((NSInteger)arr.count), @"capacity": @(DH_THUNK_COUNT), @"hooks": arr});
}

// unhook — 卸载一个 hook。默认软停(停止记录, thunk 仍透明转发); hard=true 硬卸载:
// inline 恢复目标入口原始字节、method 恢复原 IMP, 槽位标记 retired 不再复用。
static NSDictionary *tool_unhook(NSDictionary *args) {
    NSNumber *slot = args[@"slot"];
    if (![slot isKindOfClass:NSNumber.class]) return tool_err(@"slot (number) required");
    if (slot.doubleValue != floor(slot.doubleValue) || slot.doubleValue < 0 || slot.doubleValue >= DH_THUNK_COUNT)
        return tool_err(@"slot must be an integer within the hook bank");
    id hardValue = args[@"hard"];
    if (hardValue && (![hardValue isKindOfClass:NSNumber.class] || ([hardValue doubleValue] != 0 && [hardValue doubleValue] != 1)))
        return tool_err(@"hard must be a boolean");
    BOOL hard = [args[@"hard"] boolValue];
    char errbuf[256] = {0};
    int r = dh_thunk_uninstall(slot.intValue, hard ? 1 : 0, errbuf, sizeof(errbuf));
    if (r == -1) return tool_err([NSString stringWithFormat:@"slot %@ is not an active hook", slot]);
    if (r == -5) return tool_err([NSString stringWithFormat:@"slot %@: %s", slot,
                                  errbuf[0] ? errbuf : "hard unhook unsupported"]);
    if (r != 0) return tool_err([NSString stringWithFormat:@"slot %@ 卸载失败: %s", slot,
                                 errbuf[0] ? errbuf : "unknown"]);
    dh_hook_info info[DH_THUNK_COUNT];
    int n = dh_thunk_list(info, DH_THUNK_COUNT);
    const char *kind = "unknown";
    BOOL retired = NO;
    for (int i = 0; i < n; i++) {
        if (info[i].slot != slot.intValue) continue;
        kind = info[i].kind == DH_HOOK_METHOD ? "method"
             : (info[i].kind == DH_HOOK_INLINE ? "inline" : "import");
        retired = info[i].retired ? YES : NO;
        break;
    }
    BOOL restored = hard && (strcmp(kind, "inline") == 0 || strcmp(kind, "method") == 0);
    NSString *note = hard
        ? (restored
            ? @"原函数入口/IMP 已恢复；槽位 retired，不再复用。Dobby 蹦床保留以避免在途线程 use-after-free，属于有界泄漏。"
            : @"hard unhook 对 fishhook import hook 不适用，已保持软停。")
        : @"recording stopped; the thunk keeps forwarding transparently (slot not reclaimed).";
    return tool_ok(@{@"slot": slot, @"enabled": @NO, @"hard": hard ? @YES : @NO,
                     @"kind": @(kind), @"restored": restored ? @YES : @NO,
                     @"retired": retired ? @YES : @NO, @"note": note});
}

// 事件是否通过「增量过滤」(output_hex/output_len/thread_id/时间窗/stack_contains)。
// 复用于 query_events 与 correlate_request。传入的过滤值缺省(nil/0)即不约束该项。
static BOOL event_passes_extra(DHLogEntry *e,
                               NSString *outHexEq, NSString *outHexPrefix, NSNumber *outLen,
                               NSNumber *tid, uint64_t sinceMs, uint64_t untilMs, NSString *stackHas) {
    if (outLen && e.output.length != outLen.unsignedIntegerValue) return NO;
    if (tid && e.threadId != tid.unsignedLongLongValue) return NO;
    if (sinceMs && e.timestampMs < sinceMs) return NO;
    if (untilMs && e.timestampMs > untilMs) return NO;
    if (stackHas.length && [e.callStack rangeOfString:stackHas].location == NSNotFound) return NO;
    if (outHexEq.length || outHexPrefix.length) {
        NSString *oh = e.output.length ? [DHHexFromData(e.output) lowercaseString] : @"";
        if (outHexEq.length && ![oh isEqualToString:[outHexEq lowercaseString]]) return NO;
        if (outHexPrefix.length && ![oh hasPrefix:[outHexPrefix lowercaseString]]) return NO;
    }
    return YES;
}

static BOOL event_passes_context(DHLogEntry *event, NSDictionary *args) {
    NSDictionary *keys = @{@"process_generation": @"processGeneration", @"call_id": @"callId",
        @"parent_call_id": @"parentCallId", @"hook_id": @"hookId", @"phase": @"phase",@"async_task_id":@"asyncTaskId"};
    for (NSString *key in keys) {
        id value = args[key];
        if (value && (![value isKindOfClass:NSString.class] || ![value isEqual:event.eventContext[keys[key]]])) return NO;
    }
    return YES;
}

// query_events —— 过滤检索捕获事件 (最新在前), 返回摘要
static NSDictionary *tool_query_events(NSDictionary *args) {
    NSInteger cat = category_from_string(args[@"category"]);
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : @"";
    NSUInteger minSize = [args[@"min_size"] isKindOfClass:NSNumber.class] ? [args[@"min_size"] unsignedIntegerValue] : 0;
    NSUInteger maxSize = [args[@"max_size"] isKindOfClass:NSNumber.class] ? [args[@"max_size"] unsignedIntegerValue] : 0;
    uint64_t since = [args[@"since_seq"] isKindOfClass:NSNumber.class] ? [args[@"since_seq"] unsignedLongLongValue] : 0;
    NSInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] integerValue] : 100;
    if (limit <= 0 || limit > 1000) limit = 100;

    // 增量过滤参数 (Batch 1)
    NSString *outHexEq   = [args[@"output_hex"] isKindOfClass:NSString.class] ? args[@"output_hex"] : nil;
    NSString *outHexPre  = [args[@"output_hex_prefix"] isKindOfClass:NSString.class] ? args[@"output_hex_prefix"] : nil;
    NSNumber *outLen     = [args[@"output_len"] isKindOfClass:NSNumber.class] ? args[@"output_len"] : nil;
    NSNumber *tid        = [args[@"thread_id"] isKindOfClass:NSNumber.class] ? args[@"thread_id"] : nil;
    uint64_t sinceMs     = [args[@"since_ts_ms"] isKindOfClass:NSNumber.class] ? [args[@"since_ts_ms"] unsignedLongLongValue] : 0;
    uint64_t untilMs     = [args[@"until_ts_ms"] isKindOfClass:NSNumber.class] ? [args[@"until_ts_ms"] unsignedLongLongValue] : 0;
    NSString *stackHas   = [args[@"stack_contains"] isKindOfClass:NSString.class] ? args[@"stack_contains"] : nil;

    NSArray *src = [[DHLogStore shared] snapshotMatching:q category:cat minInputSize:minSize maxInputSize:maxSize];
    NSMutableArray *out = [NSMutableArray array];
    NSUInteger matched = 0;
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0; i--) {
        DHLogEntry *e = src[i];
        if (since && e.seq <= since) continue;
        if (!event_passes_context(e, args)) continue;
        if (!event_passes_extra(e, outHexEq, outHexPre, outLen, tid, sinceMs, untilMs, stackHas)) continue;
        matched++;
        if ((NSInteger)out.count < limit) [out addObject:dh_log_entry_summary(e)];
    }
    return tool_ok(@{@"count": @(out.count), @"matched": @(matched), @"events": out});
}

// wait_events —— 服务端阻塞等待，直到出现匹配事件或超时，一次返回。
//
// 为什么需要: 客户端轮询的代价不只是往返延迟。目标 App 常常要几秒才发一次请求，
// 按 50ms 轮询就是几十次请求；更糟的是轮询间隔里的命中可能被下一次 clear_events
// 冲掉，或者拿到上一轮的旧事件 —— 排查时表现为「事件看起来没产生」。
//
// 语义:
//   - since_seq 是游标。不传则用「当前最新 seq」，即只等调用之后产生的事件，
//     不会把历史事件当成本次命中。
//   - 命中即返回（不等满 timeoutMs）。返回里的 next_seq 可直接用作下次的 since_seq。
//   - 超时返回 ok 但 timeout:true，events 为空。这是正常结果，不是错误。
//   - 轮询间隔 40ms：比客户端轮询密，但每次只是内存快照，不开连接。
static NSDictionary *tool_wait_events(NSDictionary *args) {
    NSInteger cat = category_from_string(args[@"category"]);
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : @"";
    NSUInteger minSize = [args[@"min_size"] isKindOfClass:NSNumber.class] ? [args[@"min_size"] unsignedIntegerValue] : 0;
    NSUInteger maxSize = [args[@"max_size"] isKindOfClass:NSNumber.class] ? [args[@"max_size"] unsignedIntegerValue] : 0;
    NSInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] integerValue] : 20;
    if (limit <= 0 || limit > 200) limit = 20;

    NSString *outHexEq  = [args[@"output_hex"] isKindOfClass:NSString.class] ? args[@"output_hex"] : nil;
    NSString *outHexPre = [args[@"output_hex_prefix"] isKindOfClass:NSString.class] ? args[@"output_hex_prefix"] : nil;
    NSNumber *outLen    = [args[@"output_len"] isKindOfClass:NSNumber.class] ? args[@"output_len"] : nil;
    NSNumber *tid       = [args[@"thread_id"] isKindOfClass:NSNumber.class] ? args[@"thread_id"] : nil;
    NSString *stackHas  = [args[@"stack_contains"] isKindOfClass:NSString.class] ? args[@"stack_contains"] : nil;
    NSString *op        = [args[@"operation"] isKindOfClass:NSString.class] ? args[@"operation"] : nil;

    // 超时上限必须**低于客户端超时**, 否则工具正常工作却表现为失败:
    // 服务端还在等, 客户端已经报 timed out, 请求也没被取消, 服务端仍占着连接。
    // idh-cli 的 http_mcp.py 默认 timeout=15.0s（gateway 三条路径都不传 timeout），
    // 所以取 12000ms, 留 3s 给传输和客户端处理。
    NSInteger timeoutMs = [args[@"timeout_ms"] isKindOfClass:NSNumber.class] ? [args[@"timeout_ms"] integerValue] : 5000;
    if (timeoutMs < 0) timeoutMs = 0;
    if (timeoutMs > 12000) timeoutMs = 12000;

    DHLogStore *store = [DHLogStore shared];
    uint64_t since = [args[@"since_seq"] isKindOfClass:NSNumber.class]
                   ? [args[@"since_seq"] unsignedLongLongValue] : 0;
    BOOL autoSince = (since == 0);
    NSDate *startedAt = [NSDate date];
    if (autoSince) {
        // 取当前最新 seq 作为游标: 只等「调用之后」产生的事件。
        NSArray *cur = [store snapshotMatching:nil category:-1 minInputSize:0 maxInputSize:0];
        since = cur.count ? ((DHLogEntry *)cur.lastObject).seq : 0;
    }

    // 采集被暂停时新事件不可能产生, 必然烧满整个 timeout 才返回空 ——
    // 那正是这个工具要消灭的「事件看起来没产生」。直接给带原因的快速失败。
    if (store.paused) {
        return tool_ok(@{
            @"count": @0, @"timeout": @NO, @"events": @[],
            @"since_seq": @(since), @"next_seq": @(since), @"waited_ms": @0,
            @"error": @"capture is paused (set_pause) — no new events can be recorded; resume it first",
        });
    }

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:(timeoutMs / 1000.0)];
    NSArray *found = @[];
    uint64_t scannedMax = since;   // 扫到哪: 包含被过滤器排除的事件
    uint64_t returnedMax = since;  // 返回了哪: 只含真正命中并返回的事件
    while (1) {
        // 每轮必须有 autoreleasepool。25Hz × 12s = 300 轮, 每轮 snapshotMatching
        // 返回最多上万条并对关键词做 lowercaseString —— 不放进 pool 会全堆在
        // 函数返回时才释放, 在 2-3GB 设备上是几十 MB 的峰值。
        @autoreleasepool {
            NSArray *src = [store snapshotMatching:q category:cat minInputSize:minSize maxInputSize:maxSize];
            NSMutableArray *hit = [NSMutableArray array];
            for (DHLogEntry *e in src) {
                if (e.seq <= since) continue;
                if (e.seq > scannedMax) scannedMax = e.seq;
                if (op && ![e.operation isEqualToString:op]) continue;
                if (!event_passes_extra(e, outHexEq, outHexPre, outLen, tid, 0, 0, stackHas)) continue;
                [hit addObject:e];
                if (e.seq > returnedMax) returnedMax = e.seq;
                if ((NSInteger)hit.count >= limit) break;
            }
            if (hit.count) { found = hit; break; }
        }
        if ([deadline timeIntervalSinceNow] <= 0) break;
        // 40ms 一轮: 目标命中通常在毫秒级, 再密就是空转; 再疏会明显增加检测延迟。
        usleep(40 * 1000);
    }

    NSMutableArray *out = [NSMutableArray array];
    for (DHLogEntry *e in found) [out addObject:dh_log_entry_summary(e)];
    NSInteger waitedMs = (NSInteger)(-[startedAt timeIntervalSinceNow] * 1000.0);
    BOOL timedOut = (out.count == 0 && [deadline timeIntervalSinceNow] <= 0);
    return tool_ok(@{
        @"count":   @(out.count),
        @"timeout": @(timedOut),
        @"events":  out,
        @"since_seq": @(since),
        // 两个游标语义不同, 别混用:
        //   next_seq     = 已**返回**的最大 seq, 安全用于「继续等同一过滤器」;
        //   scanned_seq  = 已**判断过**的最大 seq, 包含被 operation/其它过滤器排除的。
        // 换过滤器时用 next_seq(否则会漏掉两个窗口之间只有新过滤器才匹配的事件);
        // 只想跳过已看过的时间段、不关心漏不漏时用 scanned_seq。
        @"next_seq":    @(returnedMax),
        @"scanned_seq": @(scannedMax),
        @"waited_ms":   @(waitedMs),
    });
}

// agent_ping —— 最轻量探活。
//
// 为什么需要: 引擎/目标一崩，客户端看到的是 RemoteDisconnected 或超时，
// 分不清「目标崩了」还是「这条命令很慢」。这个工具只回答「你还活着吗」，
// 是排查第一步该调的。
//
// 注意这里**没有**服务端超时: tool_get_stats 是同步调用, 无法被安全放弃。
// 客户端侧的超时(idh-cli 默认 15s)才是真正的兜底。别在这个工具的文档里
// 承诺它自己会限时 —— 那是虚假保证。
static NSDictionary *tool_agent_ping(NSDictionary *args) {
    NSDate *t0 = [NSDate date];
    // tool_get_stats 返回的是已经包装好的 MCP 响应，真实数据在 structuredContent 下。
    NSDictionary *st = tool_get_stats(@{});
    NSDictionary *proc = st[@"structuredContent"][@"process"];
    NSTimeInterval ms = -[t0 timeIntervalSinceNow] * 1000.0;
    return tool_ok(@{
        @"alive": @YES,
        // 进程内耗时, 不含网络往返。和客户端 15s 超时对比时不要当成 RTT。
        @"elapsed_ms": @((NSInteger)ms),
        @"pid": proc[@"pid"] ?: @0,
        @"app": proc[@"appName"] ?: @"",
    });
}


// correlate_request —— 以一次 net 请求为锚, 聚合时间窗内 crypto/sys 事件, 并按 X-Validator 反查命中。
// 把「AES→Hash→设 Header→发包」串成一次请求, match 块给 AI「命中即闭合」的自动化验收。
static NSDictionary *tool_correlate_request(NSDictionary *args) {
    NSNumber *netSeqN = args[@"net_seq"];
    if (![netSeqN isKindOfClass:NSNumber.class]) return tool_err(@"missing 'net_seq'");
    DHLogEntry *anchor = [[DHLogStore shared] entryWithSeq:(uint64_t)netSeqN.unsignedLongLongValue];
    if (!anchor) return tool_err([NSString stringWithFormat:@"no event with seq %@", netSeqN]);
    if (anchor.timestampMs == 0) return tool_err(@"anchor is a legacy event without timestampMs — re-capture after 1.14.0");

    uint64_t windowMs = [args[@"window_ms"] isKindOfClass:NSNumber.class] ? [args[@"window_ms"] unsignedLongLongValue] : 300;
    BOOL sameThread = [args[@"same_thread_only"] isKindOfClass:NSNumber.class] ? [args[@"same_thread_only"] boolValue] : NO;

    // include 分类集合 (默认全部)
    NSMutableSet *allow = [NSMutableSet set];
    NSArray *inc = [args[@"include"] isKindOfClass:NSArray.class] ? args[@"include"] : nil;
    for (id s in inc) { NSInteger c = category_from_string(s); if (c >= 0) [allow addObject:@(c)]; }
    BOOL allowAll = (allow.count == 0);

    // 解析锚点请求头 + URL。detail 经 dh_net_split_detail 后是纯请求 (METHOD URL + Key: Value),
    // 旧日志的 >/< 与分段标签也会被剥掉。
    NSString *req = nil, *resp = nil, *nerr = nil;
    NSInteger st = 0;
    dh_net_split_detail(anchor.detail, &req, &resp, &nerr, &st);
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    NSString *method = anchor.operation ?: @"";
    NSArray *lines = [(req ?: @"") componentsSeparatedByString:@"\n"];
    NSString *url = lines.count ? lines[0] : @"";
    if ([url hasPrefix:[method stringByAppendingString:@" "]]) url = [url substringFromIndex:method.length + 1];
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *ln = lines[i];
        if ([ln hasPrefix:@"> "]) ln = [ln substringFromIndex:2];
        NSRange colon = [ln rangeOfString:@": "];
        if (colon.location == NSNotFound) continue;
        NSString *key = [ln substringToIndex:colon.location];
        if (key.length) headers[key] = [ln substringFromIndex:colon.location + 2];
    }
    // 匹配头: 指定 match_header 则只查它, 否则扫描全部请求头(任何 base64 值都试着反查)。
    // 不再把 X-Validator 写死 —— 它只是「优先展示」的兼容默认。
    NSString *matchHeader = [args[@"match_header"] isKindOfClass:NSString.class] ? args[@"match_header"] : nil;

    // 聚合时间窗事件, 同时建 输出hex -> 首个事件 索引
    NSArray *all = [[DHLogStore shared] snapshotMatching:@"" category:-1 minInputSize:0 maxInputSize:0];
    NSMutableArray *events = [NSMutableArray array];
    NSMutableDictionary *outIndex = [NSMutableDictionary dictionary];   // hex -> @{seq,category,algorithm}
    for (DHLogEntry *e in all) {
        if (e.seq == anchor.seq || e.timestampMs == 0) continue;
        if (!allowAll && ![allow containsObject:@(e.category)]) continue;
        if (sameThread && e.threadId != anchor.threadId) continue;
        long long delta = (long long)e.timestampMs - (long long)anchor.timestampMs;
        if (llabs(delta) > (long long)windowMs) continue;
        NSString *oh = e.output.length ? [DHHexFromData(e.output) lowercaseString] : @"";
        [events addObject:@{
            @"seq": @(e.seq), @"category": @(dh_log_category_name(e.category)),
            @"deltaMs": @(delta), @"algorithm": e.algorithm ?: @"",
            @"outLen": @(e.output.length),
            @"outputHexPreview": oh.length > 16 ? [oh substringToIndex:16] : oh,
        }];
        if (oh.length && !outIndex[oh])
            outIndex[oh] = @{@"seq": @(e.seq), @"category": @(dh_log_category_name(e.category)), @"algorithm": e.algorithm ?: @""};
    }
    [events sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) { return [a[@"deltaMs"] compare:b[@"deltaMs"]]; }];

    // 反查: 每个候选头 base64 解码 -> hex, 在事件输出里找命中(泛化到任意 base64 头, 不止 X-Validator)
    NSMutableArray *matches = [NSMutableArray array];
    NSString *validatorHex = @"";   // 兼容: anchor 仍单独给 X-Validator 的解码 hex
    for (NSString *h in headers) {
        if (matchHeader && [h caseInsensitiveCompare:matchHeader] != NSOrderedSame) continue;
        NSData *dec = [[NSData alloc] initWithBase64EncodedString:headers[h] options:0];
        if (!dec.length) continue;
        NSString *hex = [DHHexFromData(dec) lowercaseString];
        if ([h caseInsensitiveCompare:@"X-Validator"] == NSOrderedSame) validatorHex = hex;
        NSDictionary *hit = outIndex[hex];
        if (hit) [matches addObject:@{@"header": h, @"decodedHex": hex, @"matchedSeq": hit[@"seq"],
                                      @"matchedCategory": hit[@"category"], @"matchedAlgorithm": hit[@"algorithm"]}];
    }
    // match 块: 兼容旧字段(X-Validator 命中优先, 否则第一个命中) + 全部命中数组 matches
    NSDictionary *primary = nil;
    for (NSDictionary *m in matches) if ([m[@"header"] caseInsensitiveCompare:@"X-Validator"] == NSOrderedSame) { primary = m; break; }
    if (!primary) primary = matches.firstObject;
    NSMutableDictionary *matchDict = [@{@"validatorOutputFound": (primary != nil) ? @YES : @NO, @"matches": matches} mutableCopy];
    if (primary) {
        matchDict[@"matchedHeader"]    = primary[@"header"];
        matchDict[@"matchedSeq"]       = primary[@"matchedSeq"];
        matchDict[@"matchedCategory"]  = primary[@"matchedCategory"];
        matchDict[@"matchedAlgorithm"] = primary[@"matchedAlgorithm"];
    }

    return tool_ok(@{
        @"anchor": @{
            @"seq": @(anchor.seq), @"timestampMs": @(anchor.timestampMs), @"threadId": @(anchor.threadId),
            @"method": method, @"url": url, @"headers": headers, @"validatorDecodedHex": validatorHex,
        },
        @"events": events,
        @"match": matchDict,
    });
}

// 把格式化调用栈字符串解析成结构化帧, 让 AI 直接拿 address 续接 disassemble_function/symbolicate,
// 不必自己正则抠地址。每行形如 "[ 0] 0  libSystem.B.dylib  0x... symbol + 44"。
static NSArray *parse_callstack_frames(NSString *cs) {
    if (![cs isKindOfClass:NSString.class] || cs.length == 0) return @[];
    static NSRegularExpression *re = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        re = [NSRegularExpression regularExpressionWithPattern:
              @"\\d+\\s+(\\S+)\\s+(0x[0-9a-fA-F]+)\\s+(.+?)\\s+\\+\\s+(\\d+)" options:0 error:nil];
    });
    NSMutableArray *frames = [NSMutableArray array];
    int idx = 0;
    for (NSString *line in [cs componentsSeparatedByString:@"\n"]) {
        NSTextCheckingResult *m = [re firstMatchInString:line options:0 range:NSMakeRange(0, line.length)];
        if (!m) continue;
        [frames addObject:@{
            @"index":   @(idx++),
            @"image":   [line substringWithRange:[m rangeAtIndex:1]],
            @"address": [line substringWithRange:[m rangeAtIndex:2]],
            @"symbol":  [line substringWithRange:[m rangeAtIndex:3]],
            @"offset":  @([[line substringWithRange:[m rangeAtIndex:4]] integerValue]),
        }];
    }
    return frames;
}

static NSDictionary *event_detail_with_frames(DHLogEntry *e, NSUInteger maxBlobBytes,
                                               BOOL includeDumps) {
    NSDictionary *detail = dh_log_entry_detail_bounded(e, maxBlobBytes, includeDumps);
    NSString *cs = detail[@"callStack"];
    if (!cs.length) return detail;
    NSMutableDictionary *out = [detail mutableCopy];
    out[@"callStackFrames"] = parse_callstack_frames(cs);
    return out;
}

// get_event —— 单条完整详情 (key / iv / 明文 / 密文 / 调用栈 + 结构化帧)
static NSDictionary *tool_get_event(NSDictionary *args) {
    NSNumber *seqN = args[@"seq"];
    if (![seqN isKindOfClass:NSNumber.class]) return tool_err(@"missing 'seq'");
    DHLogEntry *e = [[DHLogStore shared] entryWithSeq:(uint64_t)seqN.unsignedLongLongValue];
    if (!e) return tool_err([NSString stringWithFormat:@"no event with seq %@", seqN]);
    return tool_ok(event_detail_with_frames(e, NSUIntegerMax, YES));
}

// get_call —— 依据真实 token 关联入口/出口与同步后代，不通过 detail 或 TID 猜测。
static NSDictionary *tool_get_call(NSDictionary *args) {
    NSString *callID = args[@"call_id"];
    if (![callID isKindOfClass:NSString.class] || callID.length > 100) return tool_err(@"call_id required");
    NSArray *pieces = [callID componentsSeparatedByString:@":"];
    if (pieces.count != 2 || ![[NSUUID alloc] initWithUUIDString:pieces[0]] || ![pieces[1] length] ||
        [pieces[1] rangeOfCharacterFromSet:NSCharacterSet.decimalDigitCharacterSet.invertedSet].location != NSNotFound)
        return tool_err(@"call_id must contain a process generation and a decimal token");
    NSString *generation = pieces[0];
    for (NSString *field in @[@"limit", @"max_blob_bytes", @"max_output_bytes"]) {
        id value = args[field];
        if (value && (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
            !isfinite([value doubleValue]) || floor([value doubleValue]) != [value doubleValue]))
            return tool_err(@"get_call budgets must be integer numbers");
    }
    id includeChildren = args[@"include_children"];
    if (includeChildren && (![includeChildren isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)includeChildren) != CFBooleanGetTypeID()))
        return tool_err(@"include_children must be boolean");
    NSInteger limit = args[@"limit"] ? [args[@"limit"] integerValue] : 50;
    NSInteger blob = args[@"max_blob_bytes"] ? [args[@"max_blob_bytes"] integerValue] : 256;
    NSInteger byteLimit = args[@"max_output_bytes"] ? [args[@"max_output_bytes"] integerValue] : 512 * 1024;
    if (limit < 1 || limit > 200 || blob < 0 || blob > 8192 || byteLimit < 4096 || byteLimit > 2 * 1024 * 1024)
        return tool_err(@"get_call budget out of range");
    BOOL children = args[@"include_children"] ? [args[@"include_children"] boolValue] : YES;
    NSArray<DHLogEntry *> *snapshot = [[DHLogStore shared] snapshot];
    NSMutableSet *ids = [NSMutableSet setWithObject:callID];
    if (children) {
        for (unsigned depth = 0; depth < DH_CALL_DEPTH_MAX; depth++) {
            NSUInteger before = ids.count;
            for (DHLogEntry *e in snapshot) {
                NSDictionary *c = e.eventContext;
                if (![c[@"processGeneration"] isEqual:generation]) continue;
                if ([ids containsObject:c[@"parentCallId"] ?: @""] && [c[@"callId"] length]) [ids addObject:c[@"callId"]];
            }
            if (ids.count == before) break;
        }
    }
    DHLogEntry *entry = nil, *leave = nil, *aborted = nil;
    NSMutableArray *events = [NSMutableArray array]; NSUInteger matched = 0, bytes = 0;
    BOOL truncated = NO;
    for (DHLogEntry *e in snapshot) {
        NSDictionary *c = e.eventContext;
        if (![c[@"processGeneration"] isEqual:generation]) continue;
        BOOL root = [c[@"callId"] isEqual:callID];
        if (root && [c[@"phase"] isEqual:@"entry"]) entry = e;
        if (root && [c[@"phase"] isEqual:@"leave"]) leave = e;
        if (root && [c[@"phase"] isEqual:@"aborted"]) aborted = e;
        if (![ids containsObject:c[@"callId"] ?: @""] && !(children && [ids containsObject:c[@"parentCallId"] ?: @""])) continue;
        matched++;
        if (events.count >= (NSUInteger)limit || truncated) { truncated = YES; continue; }
        NSDictionary *detail = event_detail_with_frames(e, (NSUInteger)blob, NO);
        NSData *json = [NSJSONSerialization dataWithJSONObject:detail options:0 error:nil];
        if (json.length > (NSUInteger)byteLimit - bytes) { truncated = YES; continue; }
        bytes += json.length; [events addObject:detail];
    }
    if (!matched) return tool_err(@"call events are unknown or no longer retained in the bounded store");
    NSString *status = aborted ? @"aborted" : entry && leave ? @"paired"
        : entry && [entry.eventContext[@"pairing"] isEqual:@"entry-only"] ? @"entry-only"
        : entry ? @"open-or-leave-not-retained" : leave ? @"entry-not-retained" : @"root-not-retained";
    return tool_ok(@{@"callId": callID, @"processGeneration": generation, @"status": status,
        @"retainedPair": @(entry && leave), @"resultTruncated": @(truncated), @"matched": @(matched),
        @"abortedSeq":aborted?[NSString stringWithFormat:@"%llu",aborted.seq]:(id)NSNull.null,
        @"entrySeq": entry ? [NSString stringWithFormat:@"%llu", entry.seq] : (id)[NSNull null],
        @"leaveSeq": leave ? [NSString stringWithFormat:@"%llu", leave.seq] : (id)[NSNull null],
        @"parentScope": @"active-paired-synchronous-functions", @"events": events,
        @"contextLostTotal": [NSString stringWithFormat:@"%llu", dh_call_context_lost()]});
}

// export_events —— 按 seq 升序分页导出完整 JSON；固定上界避免新事件插入扰动翻页。
static NSDictionary *tool_export_events(NSDictionary *args) {
    NSNumber *afterN = [args[@"after_seq"] isKindOfClass:NSNumber.class] ? args[@"after_seq"] : nil;
    NSNumber *untilN = [args[@"until_seq"] isKindOfClass:NSNumber.class] ? args[@"until_seq"] : nil;
    if ((afterN && afterN.longLongValue < 0) || (untilN && untilN.longLongValue < 0))
        return tool_err(@"after_seq and until_seq must be >= 0");

    NSInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] integerValue] : 25;
    if (limit <= 0 || limit > 100) return tool_err(@"limit must be between 1 and 100");
    NSInteger maxBlob = [args[@"max_blob_bytes"] isKindOfClass:NSNumber.class]
        ? [args[@"max_blob_bytes"] integerValue] : 64 * 1024;
    if (maxBlob < 0 || maxBlob > 1024 * 1024)
        return tool_err(@"max_blob_bytes must be between 0 and 1048576");
    BOOL includeDumps = [args[@"include_dumps"] isKindOfClass:NSNumber.class] &&
                        [args[@"include_dumps"] boolValue];

    uint64_t afterSeq = afterN ? afterN.unsignedLongLongValue : 0;
    DHLogStore *store = [DHLogStore shared];
    uint64_t currentMax = (uint64_t)[store totalCount];
    uint64_t snapshotUntil = untilN ? MIN(untilN.unsignedLongLongValue, currentMax) : currentMax;
    if (afterSeq > snapshotUntil)
        return tool_err(@"after_seq must not exceed the effective snapshot_until_seq");

    NSInteger cat = category_from_string(args[@"category"]);
    NSString *query = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : @"";
    NSUInteger minSize = [args[@"min_size"] isKindOfClass:NSNumber.class] ? [args[@"min_size"] unsignedIntegerValue] : 0;
    NSUInteger maxSize = [args[@"max_size"] isKindOfClass:NSNumber.class] ? [args[@"max_size"] unsignedIntegerValue] : 0;
    NSString *outHexEq = [args[@"output_hex"] isKindOfClass:NSString.class] ? args[@"output_hex"] : nil;
    NSString *outHexPre = [args[@"output_hex_prefix"] isKindOfClass:NSString.class] ? args[@"output_hex_prefix"] : nil;
    NSNumber *outLen = [args[@"output_len"] isKindOfClass:NSNumber.class] ? args[@"output_len"] : nil;
    NSNumber *tid = [args[@"thread_id"] isKindOfClass:NSNumber.class] ? args[@"thread_id"] : nil;
    uint64_t sinceMs = [args[@"since_ts_ms"] isKindOfClass:NSNumber.class] ? [args[@"since_ts_ms"] unsignedLongLongValue] : 0;
    uint64_t untilMs = [args[@"until_ts_ms"] isKindOfClass:NSNumber.class] ? [args[@"until_ts_ms"] unsignedLongLongValue] : 0;
    NSString *stackHas = [args[@"stack_contains"] isKindOfClass:NSString.class] ? args[@"stack_contains"] : nil;

    NSArray *source = [store snapshotMatching:query category:cat minInputSize:minSize maxInputSize:maxSize];
    NSMutableArray *events = [NSMutableArray arrayWithCapacity:(NSUInteger)limit];
    NSUInteger matched = 0;
    uint64_t lastSeq = afterSeq;
    for (DHLogEntry *e in source) {
        if (e.seq <= afterSeq || e.seq > snapshotUntil) continue;
        if (!event_passes_extra(e, outHexEq, outHexPre, outLen, tid, sinceMs, untilMs, stackHas)) continue;
        matched++;
        if ((NSInteger)events.count >= limit) continue;
        [events addObject:event_detail_with_frames(e, (NSUInteger)maxBlob, includeDumps)];
        lastSeq = e.seq;
    }
    BOOL hasMore = matched > events.count;
    id nextAfter = hasMore ? (id)@(lastSeq) : (id)[NSNull null];
    return tool_ok(@{
        @"format": @"iosdecrypthub.events.v1",
        @"server_version": @MCP_SERVER_VERSION,
        @"process": [store processInfo] ?: @{},
        @"order": @"seq_ascending",
        @"count": @(events.count),
        @"matched_after_cursor": @(matched),
        @"max_blob_bytes": @(maxBlob),
        @"include_dumps": includeDumps ? @YES : @NO,
        @"cursor": @{
            @"after_seq": @(afterSeq),
            @"snapshot_until_seq": @(snapshotUntil),
            @"next_after_seq": nextAfter,
            @"has_more": hasMore ? @YES : @NO,
        },
        @"events": events,
        @"retention_note": @"The cursor fixes the upper sequence bound, but events can still disappear if the configured in-memory retention limit evicts them during export.",
        @"sensitive_data_warning": @"Export may contain keys, plaintext, ciphertext, tokens, paths, and request data. Store and share it as sensitive material.",
    });
}

// query_noise —— 噪声板块事件 (被过滤掉的高频调用)
static NSDictionary *tool_query_noise(NSDictionary *args) {
    NSString *b = args[@"board"];
    DHNoiseBoard board = [b isEqualToString:@"sys"] ? DHNoiseBoardSys : DHNoiseBoardCrypto;
    NSString *q = [args[@"query"] isKindOfClass:NSString.class] ? args[@"query"] : @"";
    NSInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] integerValue] : 100;
    if (limit <= 0 || limit > 1000) limit = 100;
    NSArray *src = [[DHLogStore shared] snapshotNoiseMatching:q board:board];
    NSMutableArray *out = [NSMutableArray array];
    for (NSInteger i = (NSInteger)src.count - 1; i >= 0 && (NSInteger)out.count < limit; i--)
        [out addObject:dh_log_entry_summary(src[i])];
    return tool_ok(@{@"board": (board == DHNoiseBoardSys) ? @"sys" : @"crypto",
                     @"count": @(out.count), @"events": out});
}

// list_files —— 沙箱目录列举 (Documents/Library/tmp)
static NSDictionary *tool_list_files(NSDictionary *args) {
    NSString *path = [args[@"path"] isKindOfClass:NSString.class] ? args[@"path"] : nil;
    NSError *err = nil;
    NSDictionary *d = dh_files_list_dict(path, &err);
    if (!d) return tool_err(err.localizedDescription ?: @"list failed");
    return tool_ok(d);
}

// read_file —— 沙箱文件预览 (UTF-8 文本或 Hex Dump)
static NSDictionary *tool_read_file(NSDictionary *args) {
    NSString *path = args[@"path"];
    if (![path isKindOfClass:NSString.class]) return tool_err(@"missing 'path'");
    NSUInteger limit = [args[@"limit"] isKindOfClass:NSNumber.class] ? [args[@"limit"] unsignedIntegerValue] : 4096;
    NSError *err = nil;
    NSDictionary *d = dh_files_preview_dict(path, limit, &err);
    if (!d) return tool_err(err.localizedDescription ?: @"read failed");
    return tool_ok(d);
}

// dump_status —— 可砸壳镜像清单 + 当前砸壳任务状态
static NSDictionary *tool_dump_status(NSDictionary *args) {
    return tool_ok(@{
        @"dump_images": [[DHDumpManager shared] listImagesDict] ?: @{},
        @"task_status": [[DHDumpManager shared] statusDict] ?: @{},
    });
}

// ---- 控制类 (有副作用) ----

// set_capture —— 开关某个捕获子类 (名称见 get_stats.capture)
static NSDictionary *tool_set_capture(NSDictionary *args) {
    NSString *name = args[@"name"];
    NSNumber *on = args[@"enabled"];
    if (![name isKindOfClass:NSString.class] || ![on isKindOfClass:NSNumber.class])
        return tool_err(@"need 'name' and 'enabled'");
    for (int i = 0; i < DH_CAP_SUB_COUNT; i++) {
        if ([name isEqualToString:@(dh_capture_sub_name((dh_cap_sub)i))]) {
            dh_capture_set_sub((dh_cap_sub)i, on.boolValue ? 1 : 0);
            return tool_ok(@{@"name": name, @"enabled": @(on.boolValue)});
        }
    }
    return tool_err([NSString stringWithFormat:@"unknown capture name: %@ (see get_stats.capture)", name]);
}

// set_pause —— 暂停/恢复记录 (全局或按分类)
static NSDictionary *tool_set_pause(NSDictionary *args) {
    NSNumber *paused = args[@"paused"];
    if (![paused isKindOfClass:NSNumber.class]) return tool_err(@"need 'paused' (bool)");
    DHLogStore *s = [DHLogStore shared];
    NSString *cat = args[@"category"];
    if ([cat isKindOfClass:NSString.class] && ![cat isEqualToString:@"all"]) {
        NSInteger c = category_from_string(cat);
        if (c < 0) return tool_err([NSString stringWithFormat:@"invalid category: %@", cat]);
        [s setPaused:paused.boolValue forCategory:(DHCategory)c];
        return tool_ok(@{@"category": cat, @"paused": @(paused.boolValue)});
    }
    s.paused = paused.boolValue;
    return tool_ok(@{@"category": @"all", @"paused": @(paused.boolValue)});
}

// clear_events —— 清空内存事件 (破坏性; 落盘文件不动, 仍可 /download 取回)
static NSDictionary *tool_clear_events(NSDictionary *args) {
    NSString *cat = args[@"category"];
    DHLogStore *s = [DHLogStore shared];
    if ([cat isKindOfClass:NSString.class] && ![cat isEqualToString:@"all"]) {
        NSInteger c = category_from_string(cat);
        if (c < 0) return tool_err([NSString stringWithFormat:@"invalid category: %@", cat]);
        [s clearCategory:c];
        return tool_ok(@{@"cleared": cat});
    }
    [s clearAll];
    return tool_ok(@{@"cleared": @"all"});
}

// start_dump —— 触发砸壳 (异步, 轮询 dump_status)
static NSDictionary *tool_start_dump(NSDictionary *args) {
    NSString *mode = [args[@"mode"] isKindOfClass:NSString.class] ? args[@"mode"] : @"bin";
    if (![[DHDumpManager shared] startDump:mode])
        return tool_err(@"dump already running or invalid mode (use 'bin' or 'ipa')");
    return tool_ok(@{@"started": @YES, @"mode": mode, @"note": @"poll dump_status for progress"});
}

// ---- 配置面: 改机 / 噪声规则 / 日志配置 / 审查日志 ----

// get_spoof —— 改机/越狱隐藏/反调试的整份配置快照
static NSDictionary *tool_get_spoof(NSDictionary *args) {
    return tool_ok(dh_spoof_snapshot() ?: @{});
}

// set_spoof —— 改写伪装配置 (镜像面板 op 语义), 返回更新后快照
static NSDictionary *tool_set_spoof(NSDictionary *args) {
    NSString *group = args[@"group"];
    NSString *op = args[@"op"];
    if (![group isKindOfClass:NSString.class] || ![op isKindOfClass:NSString.class])
        return tool_err(@"need 'group' (jb/anti/device) and 'op'");
    BOOL on = [args[@"on"] isKindOfClass:NSNumber.class] ? [args[@"on"] boolValue] : YES;
    NSString *text = [args[@"text"] isKindOfClass:NSString.class] ? args[@"text"] : nil;

    if ([group isEqualToString:@"jb"]) {
        if      ([op isEqualToString:@"enable"])        dh_spoof_jb_set_on(on);
        else if ([op isEqualToString:@"add_path"]      && text) dh_spoof_jb_add_path(text);
        else if ([op isEqualToString:@"remove_path"]   && text) dh_spoof_jb_remove_path(text);
        else if ([op isEqualToString:@"add_scheme"]    && text) dh_spoof_jb_add_scheme(text);
        else if ([op isEqualToString:@"remove_scheme"] && text) dh_spoof_jb_remove_scheme(text);
        else if ([op isEqualToString:@"add_image"]     && text) dh_spoof_jb_add_image(text);
        else if ([op isEqualToString:@"remove_image"]  && text) dh_spoof_jb_remove_image(text);
        else return tool_err(@"invalid jb op (enable / add_path|remove_path|add_scheme|remove_scheme|add_image|remove_image + text)");
    } else if ([group isEqualToString:@"anti"]) {
        if ([op isEqualToString:@"enable"]) dh_spoof_anti_debug_set_on(on);
        else return tool_err(@"anti supports op 'enable' only");
    } else if ([group isEqualToString:@"device"]) {
        if      ([op isEqualToString:@"enable"])    dh_spoof_device_set_on(on);
        else if ([op isEqualToString:@"randomize"]) dh_spoof_device_randomize();
        else if ([op isEqualToString:@"set"]) {
            NSString *key = args[@"key"];
            if (![key isKindOfClass:NSString.class]) return tool_err(@"device 'set' needs 'key' (hw_machine/hw_model/os_version/device_name/idfv/idfa)");
            dh_spoof_device_set_value(key, [args[@"value"] isKindOfClass:NSString.class] ? args[@"value"] : @"");
        } else return tool_err(@"invalid device op (enable / randomize / set+key+value)");
    } else {
        return tool_err(@"group must be jb / anti / device");
    }
    return tool_ok(dh_spoof_snapshot() ?: @{});
}

static DHNoiseBoard noise_board_from(NSDictionary *args) {
    return [args[@"board"] isEqualToString:@"sys"] ? DHNoiseBoardSys : DHNoiseBoardCrypto;
}

static NSDictionary *noise_config_snapshot(DHNoiseBoard b) {
    return @{@"board": (b == DHNoiseBoardSys) ? @"sys" : @"crypto",
             @"enabled": @(dh_noise_enabled_for_board(b)),
             @"patterns": dh_noise_patterns_for_board(b) ?: @[]};
}

// get_noise_config —— 某板块噪声过滤开关 + 特征串清单
static NSDictionary *tool_get_noise_config(NSDictionary *args) {
    return tool_ok(noise_config_snapshot(noise_board_from(args)));
}

// set_noise_config —— 开关 / 增删噪声特征串
static NSDictionary *tool_set_noise_config(NSDictionary *args) {
    DHNoiseBoard b = noise_board_from(args);
    NSString *op = args[@"op"];
    NSString *text = [args[@"text"] isKindOfClass:NSString.class] ? args[@"text"] : nil;
    if ([op isEqualToString:@"enable"])
        dh_noise_set_enabled_for_board(b, [args[@"on"] isKindOfClass:NSNumber.class] ? [args[@"on"] boolValue] : YES);
    else if ([op isEqualToString:@"add"] && text)    dh_noise_add_pattern_for_board(b, text);
    else if ([op isEqualToString:@"remove"] && text) dh_noise_remove_pattern_for_board(b, text);
    else return tool_err(@"op must be enable / add / remove (add|remove need 'text')");
    return tool_ok(noise_config_snapshot(b));
}

// clear_noise —— 清空某板块噪声事件 (内存, 不动落盘)
static NSDictionary *tool_clear_noise(NSDictionary *args) {
    DHNoiseBoard b = noise_board_from(args);
    [[DHLogStore shared] clearNoiseForBoard:b];
    return tool_ok(@{@"cleared": (b == DHNoiseBoardSys) ? @"sys" : @"crypto"});
}

// get_config —— 日志保留配置
static NSDictionary *tool_get_config(NSDictionary *args) {
    DHLogStore *s = [DHLogStore shared];
    return tool_ok(@{@"maxPerCategory": @([s maxPerCategory]), @"maxLogFileBytes": @([s maxLogFileBytes])});
}

// set_config —— 改日志保留 (每类内存条数 / 单文件落盘上限, 0=不限)
static NSDictionary *tool_set_config(NSDictionary *args) {
    DHLogStore *s = [DHLogStore shared];
    if ([args[@"maxEntries"] isKindOfClass:NSNumber.class]) {
        NSInteger n = [args[@"maxEntries"] integerValue];
        if (n > 0) [s setMaxPerCategory:(NSUInteger)n];
    }
    if ([args[@"maxFileBytes"] isKindOfClass:NSNumber.class]) {
        long long n = [args[@"maxFileBytes"] longLongValue];
        if (n >= 0) [s setMaxLogFileBytes:(unsigned long long)n];
    }
    return tool_ok(@{@"maxPerCategory": @([s maxPerCategory]), @"maxLogFileBytes": @([s maxLogFileBytes])});
}

// get_diag —— 审查/诊断日志时间线 (board 省略=全部板块) + 未挂上的符号清单
static NSDictionary *tool_get_diag(NSDictionary *args) {
    NSString *b = args[@"board"];
    int board = -1;
    if      ([b isEqualToString:@"general"]) board = DH_DIAG_GENERAL;
    else if ([b isEqualToString:@"crypto"])  board = DH_DIAG_CRYPTO;
    else if ([b isEqualToString:@"file"])    board = DH_DIAG_FILE;
    else if ([b isEqualToString:@"sys"])     board = DH_DIAG_SYS;
    else if ([b isEqualToString:@"dump"])    board = DH_DIAG_DUMP;
    const char *txt = dh_diag_dump(board);
    const char *unh = dh_health_hook_unhooked();
    return tool_ok(@{
        @"board":    [b isKindOfClass:NSString.class] ? b : @"all",
        @"diag":     (txt && txt[0]) ? @(txt) : @"",
        @"unhooked": (unh && unh[0]) ? @(unh) : @"",
        @"pipeline": [[DHLogStore shared] pipelineStats],
    });
}

// ============================================================
// 工具元数据 (tools/list 用) + 分发
// ============================================================
static NSArray *tool_definitions(void) {
    NSArray *base = @[
        @{
            @"name": @"get_capabilities",
            @"description": @"Handshake — call FIRST. Returns plugin version, packaging variant (dev/trollstore/rootless/roothide), CPU arch, current phase (observe|override), and per-tier hook capability flags (hook_import/hook_method/unpack). Also returns guidance.whenNoCryptoEvents: when standard crypto hooks (CCCrypt/EVP/SecKey) show no events but network traffic is encrypted, enumerate pointer+length imports (mlock/memcpy/read/send/getrandom) and capture at call time with hook_import(capture_memory) instead of attempting unsupported hooks.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"disassemble",
            @"description": @"Disassemble a hex byte string into structured instructions (ARM64/ARM/Thumb): typed operands, explicit register access, control-flow groups/targets, and bounded ARM64 MOVZ/MOVN/MOVK constant reconstruction. Constant tracking is linear and resets at control-flow boundaries; it is not CFG analysis.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"bytes": @{@"type": @"string", @"description": @"Hex-encoded machine code, e.g. \"fd7bbfa9\""},
                    @"address": @{@"type": @"string", @"description": @"Base address for listing, e.g. \"0x100000000\" (default 0)"},
                    @"arch": @{@"type": @"string", @"enum": @[@"arm64", @"arm", @"thumb"], @"description": @"Default arm64"},
                },
                @"required": @[@"bytes"],
            },
        },
        @{
            @"name": @"analyze_function",
            @"description": @"Read `size` bytes from process memory at `address` and return structured instructions. Includes typed operands/register access and bounded ARM64 move-wide constant reconstruction. Safe against unmapped addresses.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"In-process address, e.g. \"0x1029ac000\""},
                    @"size": @{@"type": @"number", @"description": @"Bytes to read (capped at 65536)"},
                    @"arch": @{@"type": @"string", @"enum": @[@"arm64", @"arm", @"thumb"], @"description": @"Default arm64"},
                },
                @"required": @[@"address", @"size"],
            },
        },
        @{
            @"name": @"disassemble_function",
            @"description": @"Disassemble the function containing `address` into structured instructions. LC_FUNCTION_STARTS normalizes an interior address to the real function start. Use byte_offset=next_byte_offset to page within that function (1024 instructions per response); decode_start is the page start and resolved_start/end remain the function bounds. Collect every page before claiming full coverage. Falls back to a low-confidence ret heuristic without metadata; paging then refuses. ARM64 constant reconstruction is local to each returned page.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"Function start address, e.g. \"0x1029ac000\""},
                    @"max_bytes": @{@"type": @"number", @"description": @"Read cap before forced stop (default 4096, max 65536)"},
                    @"byte_offset": @{@"type": @"number", @"description": @"Aligned byte offset from resolved function start (default 0). Continue using next_byte_offset; requires function metadata."},
                    @"arch": @{@"type": @"string", @"enum": @[@"arm64", @"arm", @"thumb"], @"description": @"Default arm64"},
                },
                @"required": @[@"address"],
            },
        },
        @{
            @"name": @"resolve_symbol",
            @"description": @"Resolve an exported/dynamic symbol to its runtime address via dlsym. Prefer `symbol`; deprecated `name` remains accepted for compatibility. Feed the result to disassemble_function.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"symbol": @{@"type": @"string", @"description": @"Symbol name, e.g. \"CCCrypt\" (no leading underscore)"},
                    @"name": @{@"type": @"string", @"description": @"Deprecated alias for symbol"},
                },
                @"anyOf": @[@{@"required": @[@"symbol"]}, @{@"required": @[@"name"]}],
            },
        },
        @{@"name":@"get_memory_mapping",@"description":@"Read the current process mapping at an address, following nested submaps while retaining the original query. Reports actual leaf protection and bounded raw kernel walk; does not grant permissions or modify mappings.",@"inputSchema":@{@"type":@"object",@"required":@[@"address"],@"properties":@{@"address":@{@"type":@"string"}}}},
        @{
            @"name": @"symbolicate",
            @"description": @"Resolve an address to its image and containing function. LC_FUNCTION_STARTS takes precedence over dladdr so stripped images return a high-confidence synthetic sub_<addr> instead of an unrelated exported symbol with a huge offset. Inspect symbol_source/confidence before treating a label as authoritative.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"In-process address, e.g. \"0x1029ac1f8\""},
                },
                @"required": @[@"address"],
            },
        },
        @{
            @"name": @"objc_resolve_imp",
            @"description": @"Resolve an ObjC selector to its current runtime IMP address. The current IMP may already be swizzled by another plugin; this tool does not claim to recover the pre-swizzle implementation. Returns declaring class, owner image, symbol, type encoding, and PAC-normalized address.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"selector": @{@"type": @"string", @"description": @"Selector, e.g. \"setRawT:\" or \"syncUpdateTWithUxd:tmpModel:\""},
                    @"class": @{@"type": @"string", @"description": @"Class name, e.g. \"WBValidatorModel\". Provide this OR `object`."},
                    @"object": @{@"type": @"string", @"description": @"Live instance address (hex). isa is read safely and matched against the class table — provide this OR `class`."},
                    @"method_type": @{@"type": @"string", @"description": @"\"instance\" (default), \"class\" (+ method, resolved on the metaclass), or \"auto\" (try instance then class)."},
                },
                @"required": @[@"selector"],
            },
        },
        @{
            @"name": @"objc_dump_ivars",
            @"description": @"Dump an Objective-C object's ivar table directly (whole superclass chain), with @encode types, offsets, readable values (NSData→hex, NSString→text, NSNumber→number) and the raw 8-byte slot. Use this when a class's property getters never fire (the SDK reads ivars directly) or when you do not know the field names: class+shared:true reads +sharedInstance, or pass a live object address. Read-only.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"class": @{@"type": @"string", @"description": @"Class name; combine with shared:true to read its +sharedInstance object"},
                    @"object": @{@"type": @"string", @"description": @"Live object address (hex). Provide this OR class+shared."},
                    @"shared": @{@"type": @"boolean", @"description": @"true: call +sharedInstance on the class and dump that object"},
                    @"max_bytes": @{@"type": @"number", @"description": @"Per-value display cap for hex/text (default 128, max 4096)"},
                },
            },
        },
        @{
            @"name": @"objc_export_data",
            @"description": @"Write an object's NSData/NSString ivar to a file inside the app sandbox (Documents/), so a large binary payload (key table, embedded blob) can be pulled out with scp instead of read in 4KB chunks. class+shared:true reads +sharedInstance, or pass a live object address. Returns path, byte count and the first 64 bytes as hex. Write-only to the app's own Documents directory.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"class": @{@"type": @"string", @"description": @"Class name (with shared:true)"},
                    @"object": @{@"type": @"string", @"description": @"Live object address (hex)"},
                    @"shared": @{@"type": @"boolean", @"description": @"true: use +sharedInstance"},
                    @"ivar": @{@"type": @"string", @"description": @"Ivar/property name, e.g. _pwdTable"},
                    @"name": @{@"type": @"string", @"description": @"Output filename (defaults to the ivar name + .bin)"},
                },
                @"required": @[@"ivar"],
            },
        },
        @{
            @"name": @"objc_call",
            @"description": @"Invoke an Objective-C method and return its result. Use it to turn a signing/digest facade into an ORACLE: feed controlled inputs and observe outputs instead of guessing which fields feed a hash. Arguments are marshalled as NSString (pass null for nil), up to 8; the return value is rendered as text / NSData hex / description. class_method:true calls a +method; instance calls need object (live address). Synchronous and can crash the target if the selector has side effects.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"class": @{@"type": @"string", @"description": @"Class name"},
                    @"selector": @{@"type": @"string", @"description": @"Selector, e.g. \"maHWP__unpliableness:errCode:\""},
                    @"class_method": @{@"type": @"boolean", @"description": @"true for a +method (default false)"},
                    @"args": @{@"type": @"array", @"description": @"Argument list (0..6 entries); each entry becomes an NSString, null becomes nil"},
                    @"object": @{@"type": @"string", @"description": @"Live receiver address (hex) for an instance method"},
                },
                @"required": @[@"selector"],
            },
        },
        @{
            @"name": @"find_objc_methods",
            @"description": @"Query Objective-C runtime method entities. Lists methods declared directly by matching classes and returns selector, type encoding, current IMP, class image, and current IMP image. Requires at least one filter and is paged. An IMP outside the class image is reported as an observation, not proof of swizzling.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"class": @{@"type": @"string", @"description": @"Exact class name; avoids scanning the full class list"},
                    @"class_query": @{@"type": @"string", @"description": @"Case-insensitive substring filter on class name"},
                    @"selector": @{@"type": @"string", @"description": @"Selector filter"},
                    @"match": @{@"type": @"string", @"enum": @[@"exact", @"contains", @"prefix"], @"description": @"Selector match mode (default contains)"},
                    @"image": @{@"type": @"string", @"description": @"Case-insensitive substring filter on declaring class image"},
                    @"imp_image": @{@"type": @"string", @"description": @"Case-insensitive substring filter on current IMP owner image"},
                    @"method_type": @{@"type": @"string", @"enum": @[@"instance", @"class", @"both"], @"description": @"Method kind (default both)"},
                    @"offset": @{@"type": @"number", @"description": @"Paging offset (default 0)"},
                    @"limit": @{@"type": @"number", @"description": @"Max methods returned (default 200, max 500)"},
                },
            },
        },
        @{
            @"name": @"read_memory",
            @"description": @"Read process memory at `address` and return a hex + ASCII hexdump. Safe against unmapped addresses. For inspecting data/keys/structs (not code).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"In-process address"},
                    @"size": @{@"type": @"number", @"description": @"Bytes to read (default 256, max 4096)"},
                },
                @"required": @[@"address"],
            },
        },
        @{
            @"name": @"search_memory",
            @"description": @"Scan [address, address+length) for a byte pattern or string. Skips unmapped pages. Returns hit addresses. Use to find constants/keys/xrefs.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"Start address (e.g. an image load_address)"},
                    @"length": @{@"type": @"number", @"description": @"Bytes to scan (capped at 256MB)"},
                    @"string": @{@"type": @"string", @"description": @"UTF-8 string to find (alternative to pattern)"},
                    @"pattern": @{@"type": @"string", @"description": @"Hex byte pattern to find, e.g. \"deadbeef\""},
                },
                @"required": @[@"address", @"length"],
            },
        },
        @{
            @"name": @"list_images",
            @"description": @"List loaded images that have imports and their dyld index — use this only to get a valid image_index for list_imports. Images with no imports are intentionally omitted; use list_loaded_images for the complete process map.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"query": @{@"type": @"string", @"description": @"Optional substring filter on image name"},
                },
            },
        },
        @{
            @"name": @"list_loaded_images",
            @"description": @"Complete dyld image map without import-table filtering. Returns path, UUID, scope (app/system/external), load address, slide, executable range, and FairPlay metadata. Use this to find injected dylibs and choose an analysis image.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"query": @{@"type": @"string", @"description": @"Optional case-insensitive substring filter on image name or full path"},
                    @"include_system": @{@"type": @"boolean", @"description": @"Include system/shared-cache images (default true)"},
                    @"offset": @{@"type": @"number", @"description": @"Paging offset (default 0)"},
                    @"limit": @{@"type": @"number", @"description": @"Max images returned (default 200, max 500)"},
                },
            },
        },
        @{
            @"name": @"list_imports",
            @"description": @"List the imported (undefined) symbols of a loaded image — the fishhook-rebindable candidates.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"image_index": @{@"type": @"number", @"description": @"Image index from list_images (NOT get_macho_info — different index space)"},
                    @"query": @{@"type": @"string", @"description": @"Optional substring filter"},
                    @"limit": @{@"type": @"number", @"description": @"Max symbols returned (default 500)"},
                },
                @"required": @[@"image_index"],
            },
        },
        @{
            @"name": @"get_macho_info",
            @"description": @"List loaded Mach-O images in the app bundle with load address and FairPlay encryption status.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"find_xrefs",
            @"description": @"Find who calls a symbol/address: scan an image's __TEXT,__text for direct `bl` calls to the target. Resolves import stubs to the real symbol via the runtime-bound GOT + dladdr. tier-1 only: direct BL (no BLR/BR indirect calls, no string/selector refs, no CFG). Give 'symbol' (resolved via dlsym) or 'address'.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"symbol": @{@"type": @"string", @"description": @"Target symbol name, e.g. \"CCCrypt\" (no leading underscore). Resolved via dlsym."},
                    @"address": @{@"type": @"string", @"description": @"Target runtime address (alternative to symbol), e.g. \"0x1a2345678\""},
                    @"image": @{@"type": @"string", @"description": @"Image name substring to scan (default: main executable)"},
                    @"max_results": @{@"type": @"number", @"description": @"Max call sites returned (default 256, max 2000)"},
                    @"scan_offset": @{@"type": @"number", @"description": @"Byte offset into __text (default 0; use scan.next_scan_offset to continue large images)"},
                    @"scan_size": @{@"type": @"number", @"description": @"Bytes to scan in this page (default 8MB, max 48MB; refused when host memory is low)"},
                },
            },
        },
        @{
            @"name": @"find_string_refs",
            @"description": @"Find who references a string: scan an image's __TEXT,__text for ADRP+ADD (direct) / ADRP+LDR-slot (indirect) address recovery landing in a string section (__cstring / __objc_methname / __objc_classname / __objc_methtype). tier-2A: local-window backtrack only (no cross-block/func dataflow). Give 'string' (substring match) or 'address' (exact string address).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"string": @{@"type": @"string", @"description": @"Substring to match against string contents, e.g. \"AES\""},
                    @"address": @{@"type": @"string", @"description": @"Exact string runtime address (alternative to string)"},
                    @"image": @{@"type": @"string", @"description": @"Image name substring to scan (default: main executable)"},
                    @"max_results": @{@"type": @"number", @"description": @"Max ref sites returned (default 256, max 2000)"},
                    @"scan_offset": @{@"type": @"number", @"description": @"Byte offset into __text (default 0; use scan.next_scan_offset to continue)"},
                    @"scan_size": @{@"type": @"number", @"description": @"Bytes to scan in this page (default 8MB, max 48MB; refused when host memory is low)"},
                },
            },
        },
        @{
            @"name": @"find_selector_refs",
            @"description": @"Find who sends an ObjC selector: scan __TEXT,__text for objc_msgSend call sites using the given selector. Two paths: classic (adrp+ldr x1,[__objc_selrefs] then blr/bl objc_msgSend, tracked via an x1 state machine) and modern __objc_stubs (bl objc_msgSend$sel). Only reports actual call sites (not bare selref loads); doesn't recover the receiver. tier-2B.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"selector": @{@"type": @"string", @"description": @"Selector, e.g. \"dataWithBytes:length:\""},
                    @"match": @{@"type": @"string", @"enum": @[@"exact", @"contains", @"prefix"], @"description": @"Match mode (default exact)"},
                    @"image": @{@"type": @"string", @"description": @"Image name substring to scan (default: main executable)"},
                    @"max_results": @{@"type": @"number", @"description": @"Max call sites returned (default 256, max 2000)"},
                    @"scan_offset": @{@"type": @"number", @"description": @"Byte offset into __text (default 0; use scan.next_scan_offset to continue)"},
                    @"scan_size": @{@"type": @"number", @"description": @"Bytes to scan in this page (default 8MB, max 48MB; refused when host memory is low)"},
                },
                @"required": @[@"selector"],
            },
        },
        @{
            @"name": @"find_function_refs",
            @"description": @"Internal call graph: direct BL edges between functions in the same image's __text. Give 'target' (a function address) and 'direction' (callers = who calls it, callees = what it calls, both). Only direct BL to in-__text targets (import stubs / objc_stubs are excluded). BL targets that land mid-function keep target_addr + to_func_start + to_func_offset (not assumed to be an entry). tier-3A: no BLR/BR/switch/CFG.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"target": @{@"type": @"string", @"description": @"Function address, e.g. \"0x100012340\" (from a from_func_start/to_func_start of another tool)"},
                    @"direction": @{@"type": @"string", @"enum": @[@"callers", @"callees", @"both"], @"description": @"callers (default) / callees / both"},
                    @"image": @{@"type": @"string", @"description": @"Image name substring to scan (default: main executable)"},
                    @"max_results": @{@"type": @"number", @"description": @"Max edges returned (default 256, max 2000)"},
                    @"scan_offset": @{@"type": @"number", @"description": @"Byte offset into __text (default 0; use scan.next_scan_offset to continue)"},
                    @"scan_size": @{@"type": @"number", @"description": @"Bytes to scan in this page (default 8MB, max 48MB; refused when host memory is low)"},
                },
                @"required": @[@"target"],
            },
        },
        @{
            @"name": @"list_functions",
            @"description": @"List an image's functions from LC_FUNCTION_STARTS: name (dladdr symbol or sub_<addr>), start, vmaddr (stable ID), size (approx = next start - this start). Supports name substring 'query' and offset/limit paging. The inventory backing the other xref tools.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"image": @{@"type": @"string", @"description": @"Image name substring (default: main executable)"},
                    @"query": @{@"type": @"string", @"description": @"Optional substring filter on function name"},
                    @"offset": @{@"type": @"number", @"description": @"Paging offset into the filtered list (default 0)"},
                    @"limit": @{@"type": @"number", @"description": @"Max functions returned (default 200, max 2000)"},
                },
            },
        },
        // ---- 取证: 读 ----
        @{
            @"name": @"get_stats",
            @"description": @"Forensic overview: captured-event counts per category, capture toggles, host process info, hook health, on-disk log bytes, noise counts.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"query_events",
            @"description": @"Search captured runtime events (crypto/file/system) — the core forensic feed. Returns summaries newest-first. Use get_event for a full record.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"category": @{@"type": @"string", @"enum": @[@"all", @"digest", @"hmac", @"sym", @"asym", @"file", @"sys", @"net", @"keychain", @"other"], @"description": @"Filter by category (default all). 'net'=network, 'keychain'=Keychain items."},
                    @"query": @{@"type": @"string", @"description": @"Keyword filter (algorithm/path/preview)"},
                    @"min_size": @{@"type": @"number", @"description": @"Min input bytes"},
                    @"max_size": @{@"type": @"number", @"description": @"Max input bytes (0 = no cap)"},
                    @"since_seq": @{@"type": @"number", @"description": @"Only events with seq > this (incremental polling)"},
                    @"output_hex": @{@"type": @"string", @"description": @"Exact output match (case-insensitive hex). Decode a header/token to hex and find which crypto op produced it."},
                    @"output_hex_prefix": @{@"type": @"string", @"description": @"Output hex prefix match (e.g. MD5 s= first 8 chars)"},
                    @"output_len": @{@"type": @"number", @"description": @"Exact output byte length (e.g. 32 for SHA256/AES block)"},
                    @"thread_id": @{@"type": @"number", @"description": @"Only events on this thread"},
                    @"since_ts_ms": @{@"type": @"number", @"description": @"Only events with timestampMs >= this"},
                    @"until_ts_ms": @{@"type": @"number", @"description": @"Only events with timestampMs <= this"},
                    @"stack_contains": @{@"type": @"string", @"description": @"Only events whose call stack contains this substring (e.g. an address/module)"},
                    @"limit": @{@"type": @"number", @"description": @"Max results (default 100, max 1000)"},
                },
            },
        },
        @{
            @"name": @"wait_events",
            @"description": @"Block on the server until a matching event arrives or the timeout expires, then return once. This is the replacement for client-side polling loops: no repeated round trips, no missed hits between polls, no stale events. Returns timeout:true with an empty list on expiry (that is a normal result, not an error). Two cursors come back: next_seq = highest seq RETURNED (safe to feed back as since_seq when you keep the same filter), scanned_seq = highest seq EXAMINED including filtered-out events (use it only when you do not need the gap — feeding it back after changing operation/query can skip events only the new filter would match).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"category": @{@"type": @"string", @"enum": @[@"all", @"digest", @"hmac", @"sym", @"asym", @"file", @"sys", @"net", @"keychain", @"other"], @"description": @"Filter by category (default all)"},
                    @"query": @{@"type": @"string", @"description": @"Keyword filter (algorithm/path/preview)"},
                    @"operation": @{@"type": @"string", @"description": @"Exact operation/label match, e.g. the label you gave hook_inline"},
                    @"min_size": @{@"type": @"number", @"description": @"Min input bytes"},
                    @"max_size": @{@"type": @"number", @"description": @"Max input bytes (0 = no cap)"},
                    @"since_seq": @{@"type": @"number", @"description": @"Wait for events with seq > this. Omit (or 0) to use the current newest seq — i.e. only wait for events produced AFTER this call"},
                    @"output_hex": @{@"type": @"string", @"description": @"Exact output match (case-insensitive hex)"},
                    @"output_hex_prefix": @{@"type": @"string", @"description": @"Output hex prefix match"},
                    @"output_len": @{@"type": @"number", @"description": @"Exact output byte length"},
                    @"thread_id": @{@"type": @"number", @"description": @"Only events on this thread"},
                    @"stack_contains": @{@"type": @"string", @"description": @"Only events whose call stack contains this substring"},
                    @"limit": @{@"type": @"number", @"description": @"Max results to return once matched (default 20, max 200)"},
                    @"timeout_ms": @{@"type": @"number", @"description": @"How long to wait (default 5000, max 12000). Returns as soon as something matches. Capped below the idh-cli client timeout (15s) on purpose"},
                },
            },
        },
        @{
            @"name": @"agent_ping",
            @"description": @"Cheapest possible liveness probe. Answers only 'is the engine still responsive' and returns rtt_ms. Use it FIRST when a call hangs or the connection drops, to tell 'target crashed' apart from 'this command is just slow' — those two look identical to an HTTP client.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{},
            },
        },
        @{
            @"name": @"correlate_request",
            @"description": @"Anchor on a captured network request (net_seq) and gather all crypto/keychain/net events within window_ms, sorted by deltaMs. Base64-decodes the request headers and reports which event's output matches each — 'matches' lists every header→event hit; 'match' surfaces the primary one (X-Validator first, else the first). Pass match_header to restrict to one header.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"net_seq": @{@"type": @"number", @"description": @"seq of the anchor network event (from query_events category=net)"},
                    @"window_ms": @{@"type": @"number", @"description": @"Time window around the anchor (default 300)"},
                    @"include": @{@"type": @"array", @"items": @{@"type": @"string"}, @"description": @"Categories to include, e.g. [\"digest\",\"hmac\",\"sym\",\"keychain\",\"net\"] (default all)"},
                    @"same_thread_only": @{@"type": @"boolean", @"description": @"Only events on the anchor's thread (default false)"},
                    @"match_header": @{@"type": @"string", @"description": @"Restrict reverse-match to one request header (e.g. \"X-Validator\"); default scans all base64 headers"},
                },
                @"required": @[@"net_seq"],
            },
        },
        @{
            @"name": @"get_event",
            @"description": @"Full detail of one captured event by seq: algorithm, key, IV, plaintext, ciphertext (hex + utf8 + hexdump), and the app-level call stack — both as text (callStack) and structured frames (callStackFrames: [{index,image,address,symbol,offset}]) you can feed straight into disassemble_function / symbolicate.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"seq": @{@"type": @"number", @"description": @"Event sequence number (from query_events)"}},
                @"required": @[@"seq"],
            },
        },
        @{
            @"name": @"export_events",
            @"description": @"Export retained full events as upper-bound-stable, paged JSON for offline analysis. Results are seq-ascending. Reuse cursor.snapshot_until_seq as until_seq and cursor.next_after_seq as after_seq until has_more=false. Blob content is capped per field (default 64KB, max 1MB) and marked with <field>Truncated; hexdumps are off by default to avoid duplicating hex data. The response contains highly sensitive keys/plaintext/tokens and must be handled accordingly.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"category": @{@"type": @"string", @"enum": @[@"all", @"digest", @"hmac", @"sym", @"asym", @"file", @"sys", @"net", @"keychain", @"other"], @"description": @"Filter by category (default all)"},
                    @"query": @{@"type": @"string", @"description": @"Keyword filter (algorithm/path/content)"},
                    @"after_seq": @{@"type": @"number", @"description": @"Exclusive paging cursor (default 0)"},
                    @"until_seq": @{@"type": @"number", @"description": @"Inclusive stable snapshot upper bound; reuse cursor.snapshot_until_seq on later pages"},
                    @"limit": @{@"type": @"number", @"description": @"Full records per page (default 25, max 100)"},
                    @"max_blob_bytes": @{@"type": @"number", @"description": @"Max bytes encoded from each key/iv/input/output field (default 65536, max 1048576; 0 omits blob content but preserves lengths)"},
                    @"include_dumps": @{@"type": @"boolean", @"description": @"Include human-readable hexdumps in addition to hex (default false)"},
                    @"min_size": @{@"type": @"number", @"description": @"Min input bytes"},
                    @"max_size": @{@"type": @"number", @"description": @"Max input bytes (0 = no cap)"},
                    @"output_hex": @{@"type": @"string", @"description": @"Exact output hex match"},
                    @"output_hex_prefix": @{@"type": @"string", @"description": @"Output hex prefix match"},
                    @"output_len": @{@"type": @"number", @"description": @"Exact output byte length"},
                    @"thread_id": @{@"type": @"number", @"description": @"Only events on this thread"},
                    @"since_ts_ms": @{@"type": @"number", @"description": @"Only events with timestampMs >= this"},
                    @"until_ts_ms": @{@"type": @"number", @"description": @"Only events with timestampMs <= this"},
                    @"stack_contains": @{@"type": @"string", @"description": @"Only events whose call stack contains this substring"},
                },
            },
        },
        @{
            @"name": @"query_noise",
            @"description": @"List noise-filtered events (high-frequency calls diverted from the main feed).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"], @"description": @"Noise board (default crypto)"},
                    @"query": @{@"type": @"string", @"description": @"Keyword filter"},
                    @"limit": @{@"type": @"number", @"description": @"Max results (default 100)"},
                },
            },
        },
        @{
            @"name": @"list_files",
            @"description": @"List sandbox files/dirs under the host app's Documents/Library/tmp (empty path = the three roots).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"path": @{@"type": @"string", @"description": @"Relative sandbox path (empty for roots)"}},
            },
        },
        @{
            @"name": @"read_file",
            @"description": @"Preview a sandbox file as UTF-8 text or hex dump.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"path": @{@"type": @"string", @"description": @"Relative sandbox file path"},
                    @"limit": @{@"type": @"number", @"description": @"Max bytes to preview (default 4096)"},
                },
                @"required": @[@"path"],
            },
        },
        @{
            @"name": @"dump_status",
            @"description": @"List dumpable (in-memory, App-bundle) Mach-O images with encryption status, plus current unpacking task state.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        // ---- 取证: 控制 (有副作用) ----
        @{
            @"name": @"set_capture",
            @"description": @"Enable/disable a capture subtype (names from get_stats.capture, e.g. CCCrypt, open, dlopen).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"name": @{@"type": @"string", @"description": @"Capture subtype name"},
                    @"enabled": @{@"type": @"boolean", @"description": @"true to capture, false to skip"},
                },
                @"required": @[@"name", @"enabled"],
            },
        },
        @{
            @"name": @"set_pause",
            @"description": @"Pause/resume event recording, globally or for one category.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"paused": @{@"type": @"boolean", @"description": @"true to pause, false to resume"},
                    @"category": @{@"type": @"string", @"description": @"Category to target, or 'all' (default all)"},
                },
                @"required": @[@"paused"],
            },
        },
        @{
            @"name": @"clear_events",
            @"description": @"Clear in-memory captured events (destructive). On-disk log is untouched and still downloadable.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"category": @{@"type": @"string", @"description": @"Category to clear, or 'all' (default all)"}},
            },
        },
        @{
            @"name": @"start_dump",
            @"description": @"Trigger on-device unpacking (decrypt loaded images). Async — poll dump_status for progress and artifacts.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"mode": @{@"type": @"string", @"enum": @[@"bin", @"ipa"], @"description": @"'bin' = decrypted binaries zip; 'ipa' = re-signable IPA (default bin)"}},
            },
        },
        // ---- 配置面: 改机 / 噪声规则 / 日志配置 / 审查日志 ----
        @{
            @"name": @"get_spoof",
            @"description": @"Get the anti-detection config: jailbreak-hiding (paths/schemes/injection-image cloaking), anti-debug, and device-spoofing (改机) values.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"set_spoof",
            @"description": @"Change anti-detection config. Returns the updated snapshot. group=jb: enable / add_path|remove_path|add_scheme|remove_scheme|add_image|remove_image (+text). group=anti: enable. group=device: enable / randomize / set (+key +value).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"group": @{@"type": @"string", @"enum": @[@"jb", @"anti", @"device"], @"description": @"jb=jailbreak-hide, anti=anti-debug, device=改机"},
                    @"op": @{@"type": @"string", @"description": @"enable/randomize/set or jb list ops"},
                    @"on": @{@"type": @"boolean", @"description": @"For op=enable"},
                    @"text": @{@"type": @"string", @"description": @"Path/scheme/image for jb add|remove ops"},
                    @"key": @{@"type": @"string", @"description": @"device set key: hw_machine/hw_model/os_version/device_name/idfv/idfa"},
                    @"value": @{@"type": @"string", @"description": @"device set value"},
                },
                @"required": @[@"group", @"op"],
            },
        },
        @{
            @"name": @"get_noise_config",
            @"description": @"Get a noise board's filter state: enabled flag + pattern list (events matching a pattern are diverted from the main feed).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"], @"description": @"Default crypto"}},
            },
        },
        @{
            @"name": @"set_noise_config",
            @"description": @"Toggle a noise board or add/remove a noise pattern. Returns updated config.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"]},
                    @"op": @{@"type": @"string", @"enum": @[@"enable", @"add", @"remove"]},
                    @"on": @{@"type": @"boolean", @"description": @"For op=enable"},
                    @"text": @{@"type": @"string", @"description": @"Pattern for add/remove"},
                },
                @"required": @[@"op"],
            },
        },
        @{
            @"name": @"clear_noise",
            @"description": @"Clear a noise board's in-memory events (on-disk untouched).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"board": @{@"type": @"string", @"enum": @[@"crypto", @"sys"]}},
            },
        },
        @{
            @"name": @"get_config",
            @"description": @"Get log retention config: in-memory entries per category and on-disk log file cap.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"set_config",
            @"description": @"Change log retention. Returns updated config.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"maxEntries": @{@"type": @"number", @"description": @"Max in-memory events per category"},
                    @"maxFileBytes": @{@"type": @"number", @"description": @"On-disk log cap in bytes (0 = unlimited)"},
                },
            },
        },
        @{
            @"name": @"get_diag",
            @"description": @"Get the diagnostic/audit log timeline (hook health, persistence, service events) and the list of symbols that failed to hook. Omit board for all boards.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"board": @{@"type": @"string", @"enum": @[@"general", @"crypto", @"file", @"sys", @"dump"], @"description": @"Diag board (default all)"}},
            },
        },
        @{
            @"name": @"get_capture_coverage",
            @"description": @"抓包/加密覆盖自检: 逐层检查本进程导入表, 报告哪些 hook 层真正可用(NSURLSession / OpenSSL TLS / Apple SecureTransport / BSD socket / Network.framework / Security RSA / OpenSSL RSA / CommonCrypto), 并列出 blind_spots —— 那些『未被本 App 使用或已静态链接』因而抓不到的层。用于回答「为什么抓不到这个请求/这段加密」。",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"get_webkit_probe",
            @"description": @"Get the optional WKWebView JS network probe config. Default disabled. When enabled, newly created WKWebViews get a document-start script that reports fetch/XHR/WebSocket/sendBeacon to the host event feed as algorithm WEBKIT-PROBE.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"set_webkit_probe",
            @"description": @"Configure the optional WKWebView JS network probe. Changes affect newly created WKWebViews; reload the page or recreate the WebView. Domain allow/deny entries match hostname or subdomains. redact=true replaces Cookie/Authorization/token-like header values.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"enabled": @{@"type": @"boolean", @"description": @"Enable document-start JS probe"},
                    @"redact":  @{@"type": @"boolean", @"description": @"Redact sensitive header values (default true)"},
                    @"allow":   @{@"type": @"array", @"items": @{@"type": @"string"}, @"description": @"Optional allowlist of hostnames; empty means all"},
                    @"deny":    @{@"type": @"array", @"items": @{@"type": @"string"}, @"description": @"Optional denylist of hostnames"},
                },
            },
        },
        // ===== 动态 hook (一期: record-only) — 能力见 get_capabilities.capabilities =====
        @{
            @"name": @"hook_import",
            @"description": @"Install a record-only hook on an imported C symbol via fishhook (GOT rebind). On each call it snapshots arg registers x0-x8 + backtrace, records an event (category 'other', algorithm 'import-hook'), then transparently forwards to the original. Only works for symbols that appear in some image's import table (check with list_imports); statically-linked symbols cannot be rebound. When standard crypto hooks miss, enumerate pointer+length imports (mlock/memcpy/read/send/getrandom) and use capture_memory to copy the buffer at call time; a later read_memory is usually too late because the buffer may already be freed or reused. Observe-only — does not alter behavior.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"symbol": @{@"type": @"string", @"description": @"Imported symbol name, no leading underscore, e.g. \"SSL_write\""},
                    @"label":  @{@"type": @"string", @"description": @"Optional note appended to the event name"},
                    @"describe_args": @{@"type": @"boolean", @"description": @"true 时尝试把前 4 个参数里「像可打印 C 字符串」的读出来(如 getaddrinfo 的域名、dlopen 的路径); 默认 false",},
                    @"capture_return": @{@"type": @"boolean", @"description": @"true 时记录该函数返回值（x0；NSData→hex / NSString→文本 / 其它→description）。命中会变成两条事件：进入一条、返回一条（带 ret=）。代价是这层栈帧留到原函数返回；默认 false"},
                    @"capture_after": @{@"type": @"boolean", @"description": @"true 时把 capture_memory 的 ptr_arg 当成「调用之后才写好的输出缓冲」读（CCHmac 的 digest 出参、CCCrypt 的密文出参）。必须配 capture_memory 指定 ptr_arg；会自动启用返回值记录（post 路径）。默认 false"},
                    @"capture_multi": @{@"type": @"string", @"description": @"多窗口抓取: 一次 hook 同时记录多个寄存器指向的内存, 换寄存器不必重启进程（一个 inline 目标只能装一个 hook 且槽位不回收）。语法 \"x0:64,x3:32,x5:128\"，寄存器 x0-x8，:N 为字节数，省略则用 capture_max_bytes。结果以 win xN @addr = N bytes: hex 写进事件 detail。默认关闭"},
                    @"capture_ret_multi": @{@"type": @"string", @"description": @"返回值寄存器的多窗口(仅 post 路径)。语法同 capture_multi。用于「函数返回 (status, buffer)」这种 ABI —— 那块内存在返回后可能立刻被释放, 只能在这里读。结果以 ret xN @addr = N bytes: hex 写进 detail"},
                    @"capture_memory": @{
                        @"type": @"object",
                        @"description": @"命中瞬间按寄存器参数抓一段内存到事件 input(hex/utf8)。不会事后回读, 因此能在缓冲区释放/复用前拿到 key、IV、明文。标准 crypto hook 全空时, 这是抓静态链接加密库 key 的主要手段: 先用 list_imports 找 mlock/memcpy/read/send 等「指针+长度」导入, 再在此配置。ptr_arg 是 x 寄存器索引(0..8), len_arg 指定哪个寄存器是长度(-1=固定抓 max_bytes), max_bytes 上限 8192。例: mlock 的 key 缓冲 → {ptr_arg:0, len_arg:1, max_bytes:4096}",
                        @"properties": @{
                            @"ptr_arg":   @{@"type": @"number", @"description": @"指针参数所在 x 寄存器索引 0..8; 默认 0"},
                            @"len_arg":   @{@"type": @"number", @"description": @"长度参数所在 x 寄存器索引 0..8; -1 表示用 max_bytes 固定长度; 默认 -1"},
                            @"max_bytes": @{@"type": @"number", @"description": @"单次最多拷贝字节数 1..8192; 默认 256"},
                        },
                    },
                },
                @"required": @[@"symbol"],
            },
        },
        @{
            @"name": @"hook_method",
            @"description": @"Install a record-only hook on an Objective-C method via method_setImplementation swizzle. On each call it snapshots self (x0), _cmd/SEL (x1), and arg registers, records an event (category 'other', algorithm 'objc-hook'), then forwards to the original IMP. Observe-only. unhook {hard:true} restores the original IMP and retires the slot; reinstalling the same Method after hard unhook reuses that retired slot when its IMP is still the original.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"class":       @{@"type": @"string", @"description": @"ObjC class name, e.g. \"NSURLSession\""},
                    @"selector":    @{@"type": @"string", @"description": @"Selector, e.g. \"dataTaskWithRequest:completionHandler:\""},
                    @"classMethod": @{@"type": @"boolean", @"description": @"true for a class (+) method; default false (instance -)"},
                    @"describe_args": @{@"type": @"boolean", @"description": @"true 时反引用前几个参数内容(NSData→hex 前缀 / NSString→文本 / 其它→description), 直接看明文、密钥、密文; 默认 false",},
                    @"capture_return": @{@"type": @"boolean", @"description": @"true 时记录该函数返回值（x0；NSData→hex / NSString→文本 / 其它→description）。命中会变成两条事件：进入一条、返回一条（带 ret=）。代价是这层栈帧留到原函数返回；默认 false"},
                    @"capture_after": @{@"type": @"boolean", @"description": @"true 时把 capture_memory 的 ptr_arg 当成「调用之后才写好的输出缓冲」读（CCHmac 的 digest 出参、CCCrypt 的密文出参）。必须配 capture_memory 指定 ptr_arg；会自动启用返回值记录（post 路径）。默认 false"},
                    @"capture_multi": @{@"type": @"string", @"description": @"多窗口抓取: 一次 hook 同时记录多个寄存器指向的内存, 换寄存器不必重启进程（一个 inline 目标只能装一个 hook 且槽位不回收）。语法 \"x0:64,x3:32,x5:128\"，寄存器 x0-x8，:N 为字节数，省略则用 capture_max_bytes。结果以 win xN @addr = N bytes: hex 写进事件 detail。默认关闭"},
                    @"capture_ret_multi": @{@"type": @"string", @"description": @"返回值寄存器的多窗口(仅 post 路径)。语法同 capture_multi。用于「函数返回 (status, buffer)」这种 ABI —— 那块内存在返回后可能立刻被释放, 只能在这里读。结果以 ret xN @addr = N bytes: hex 写进 detail"},
                    @"capture_memory": @{
                        @"type": @"object",
                        @"description": @"命中瞬间按 x 寄存器参数抓一段内存到事件 input。x0=self, x1=_cmd, x2..=方法参数。用于 ObjC 方法参数里裸指针+长度的加密缓冲。",
                        @"properties": @{
                            @"ptr_arg":   @{@"type": @"number", @"description": @"指针参数所在 x 寄存器索引 0..8; 默认 0"},
                            @"len_arg":   @{@"type": @"number", @"description": @"长度参数所在 x 寄存器索引 0..8; -1 表示用 max_bytes 固定长度; 默认 -1"},
                            @"max_bytes": @{@"type": @"number", @"description": @"单次最多拷贝字节数 1..8192; 默认 256"},
                        },
                    },
                },
                @"required": @[@"class", @"selector"],
            },
        },
        @{
            @"name": @"hook_inline",
            @"description": @"Install a record-only inline hook (Dobby backend) on ANY native function: module+symbol or an absolute code address. Unlike hook_import (GOT) this also works for statically linked functions and direct calls inside a module. On each hit it snapshots x0-x8 + call stack, then tail-calls the original function's trampoline, so the original return value and behavior are preserved (entry observation only). Events land in category 'other' as algorithm 'inline-hook'. unhook defaults to soft stop; unhook {hard:true} restores the original entry bytes via DobbyCodePatch and retires the slot (Dobby trampoline is kept to avoid in-flight use-after-free). Available in the arm64 jailbreak build; arm64e slice refuses instead of silently falling back.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"module":  @{@"type": @"string", @"description": @"Loaded image name/path, e.g. \"libsystem_kernel.dylib\" or \"/var/jb/usr/lib/libfoo.dylib\"; omit to search RTLD_DEFAULT"},
                    @"symbol":  @{@"type": @"string", @"description": @"Exported symbol name, e.g. \"getpid\" or \"_ZN...\""},
                    @"addr":    @{@"type": @"string", @"description": @"Absolute executable address (hex string like \"0x1004a2b30\" or number); use instead of symbol when the target is not exported"},
                    @"label":   @{@"type": @"string", @"description": @"Display name for list_hooks"},
                    @"describe_args": @{@"type": @"boolean", @"description": @"true 时把前几个参数里像可打印 C 字符串的内容记进事件（与 hook_import 一致）；默认 false",},
                    @"capture_return": @{@"type": @"boolean", @"description": @"true 时记录该函数返回值（x0；NSData→hex / NSString→文本 / 其它→description）。命中会变成两条事件：进入一条、返回一条（带 ret=）。代价是这层栈帧留到原函数返回；默认 false"},
                    @"capture_after": @{@"type": @"boolean", @"description": @"true 时把 capture_memory 的 ptr_arg 当成「调用之后才写好的输出缓冲」读（CCHmac 的 digest 出参、CCCrypt 的密文出参）。必须配 capture_memory 指定 ptr_arg；会自动启用返回值记录（post 路径）。默认 false"},
                    @"capture_multi": @{@"type": @"string", @"description": @"多窗口抓取: 一次 hook 同时记录多个寄存器指向的内存, 换寄存器不必重启进程（一个 inline 目标只能装一个 hook 且槽位不回收）。语法 \"x0:64,x3:32,x5:128\"，寄存器 x0-x8，:N 为字节数，省略则用 capture_max_bytes。结果以 win xN @addr = N bytes: hex 写进事件 detail。默认关闭"},
                    @"capture_ret_multi": @{@"type": @"string", @"description": @"返回值寄存器的多窗口(仅 post 路径)。语法同 capture_multi。用于「函数返回 (status, buffer)」这种 ABI —— 那块内存在返回后可能立刻被释放, 只能在这里读。结果以 ret xN @addr = N bytes: hex 写进 detail"},
                    @"capture_memory": @{
                        @"type": @"object",
                        @"description": @"命中瞬间按 x 寄存器参数抓一段内存到事件 input（x0..x8）。",
                        @"properties": @{
                            @"ptr_arg":   @{@"type": @"number", @"description": @"指针参数所在 x 寄存器索引 0..8；默认 0"},
                            @"len_arg":   @{@"type": @"number", @"description": @"长度参数所在 x 寄存器索引 0..8；-1 表示用 max_bytes 固定长度；默认 -1"},
                            @"max_bytes": @{@"type": @"number", @"description": @"单次最多拷贝字节数 1..8192；默认 256"},
                        },
                    },
                },
            },
        },
        @{
            @"name": @"trace_function",
            @"description": @"QBDI instruction-level trace of ONE function: creates a one-shot QBDI VM, instruments the target's module, calls the function on the calling thread with up to 8 integer/pointer arguments, records up to max_insns instructions (instruction + time budgets), then destroys the VM. REPLAY semantics: the function is executed once under instrumentation, so side effects are real; only x0-x7 args are seeded (no stack/float args). Returns retval, stop_reason, truncated, duration and the instruction list. Available in the arm64 jailbreak build only.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"module": @{@"type": @"string", @"description": @"Loaded image name/path; omit to search RTLD_DEFAULT"},
                    @"symbol": @{@"type": @"string", @"description": @"Exported symbol to call/trace, e.g. \"getpid\""},
                    @"addr":   @{@"type": @"string", @"description": @"Absolute code address (hex string or number); alternative to symbol"},
                    @"args":   @{@"type": @"array", @"items": @{@"type": @"number"}, @"description": @"Up to 8 integer/pointer arguments (x0-x7). Numbers or hex strings are accepted."},
                    @"max_insns": @{@"type": @"number", @"description": @"Recording budget 1..4096; default 256"},
                    @"max_ms":    @{@"type": @"number", @"description": @"Wall-clock budget 50..10000 ms; default 3000. The first trace in a process pays QBDI JIT warmup (observed >800 ms on a real app), so a small budget can end with stop_reason=time-limit on the first call."},
                },
            },
        },
        @{
            @"name": @"list_hooks",
            @"description": @"List all dynamic hooks installed this session (slot, kind, name, hit count, enabled, retired). Slots are monotonic; a soft-disabled hook shows enabled=false, a hard-unhooked hook shows retired=true.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"unhook",
            @"description": @"Uninstall a dynamic hook by slot. Default soft stop: recording stops, thunk keeps forwarding, patch stays. hard=true restores the original code (inline: saved entry bytes via DobbyCodePatch; method: original IMP) and marks the slot retired; import hooks only support soft. Hard unhook is best-effort against already-running threads (in-flight calls finish through the retained trampoline).",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"slot": @{@"type": @"number", @"description": @"Hook slot id"}, @"hard": @{@"type": @"boolean", @"description": @"true: restore original code/IMP and retire the slot; false/default: only stop recording"}},
                @"required": @[@"slot"],
            },
        },
    ];
    NSMutableArray *tools = [NSMutableArray array];
    NSSet *mutations = [NSSet setWithArray:@[@"hook_method", @"hook_inline", @"hook_import", @"unhook", @"trace_function", @"objc_call", @"run_hook_selftest", @"trace_live_arm", @"trace_live_cancel", @"run_live_selftest"]];
    for (NSDictionary *definition in base) {
        NSMutableDictionary *d = [definition mutableCopy];
        NSMutableDictionary *schema = [d[@"inputSchema"] mutableCopy];
        NSMutableDictionary *properties = [schema[@"properties"] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSString *name = d[@"name"];
        if ([mutations containsObject:name]) {
            properties[@"process_generation"] = @{@"type": @"string", @"description": @"Current processGeneration from get_capabilities; stale/missing generations are rejected before mutation"};
            NSMutableArray *required = [schema[@"required"] mutableCopy] ?: [NSMutableArray array];
            [required addObject:@"process_generation"]; schema[@"required"] = required;
        }
        if ([name hasPrefix:@"hook_"] && ![name isEqualToString:@"hook_method"]) {
            properties[@"abi"] = @{@"type": @"object", @"description": @"Required for C post capture: fixed GPR declaration, no variadic/float/aggregate/exception unwinding",
                @"properties": @{@"arguments": @{@"type": @"array", @"maxItems": @32, @"items": @{@"type": @"string", @"enum": @[@"pointer", @"object", @"u64", @"i64", @"u32", @"i32", @"u16", @"i16", @"u8", @"i8", @"bool"]}},
                    @"return": @{@"type": @"string", @"enum": @[@"void", @"pointer", @"object", @"u64", @"i64", @"u32", @"i32", @"u16", @"i16", @"u8", @"i8", @"bool"]},
                    @"variadic": @{@"type": @"boolean"}, @"exception_unwind": @{@"type": @"boolean"}}, @"required": @[@"arguments", @"return"]};
        }
        if ([name isEqualToString:@"hook_method"]) {
            properties[@"post_abi"] = @{@"type": @"string", @"enum": @[@"fixed-nonvariadic"],
                @"description": @"Required for post capture: caller confirms fixed nonvariadic prototype; Objective-C metadata alone cannot detect ... methods"};
        }
        if ([name isEqualToString:@"query_events"]) {
            for (NSString *key in @[@"process_generation", @"call_id", @"parent_call_id", @"hook_id", @"phase",@"async_task_id"])
                properties[key] = @{@"type": @"string", @"description": @"Exact structured event-context filter; legacy records without the field do not match"};
        }
        if ([name isEqualToString:@"trace_function"])
            properties[@"buffers"] = @{@"type":@"array",@"maxItems":@8,
                @"description":@"Optional call-owned mutable copies for pointer arguments; released after replay. At most 8192 bytes each / 32768 total. Supply matching args/lengths and a known fixed GPR prototype.",
                @"items":@{@"type":@"object",@"required":@[@"arg",@"hex"],@"properties":@{
                    @"arg":@{@"type":@"integer",@"minimum":@0,@"maximum":@7},@"hex":@{@"type":@"string",@"maxLength":@16384}}}};
        if ([name isEqualToString:@"trace_function"]) {
            d[@"description"] = @"QBDI one-shot replay of a known fixed-GPR function (up to eight arguments, no stack/float/aggregate reconstruction). Supports linked arm64 and PAC-enabled arm64e builds. Optional buffers create call-owned mutable copies for pointer arguments, returned as bounded afterHex. Side effects are real. Check call_ok, retval_valid, stop_reason and instruction coverage; an early stop is not a valid function result. Instruction/time limits are cooperative, not a hard cancellation of uninstrumented native calls.";
            properties[@"args"] = @{@"type":@"array",@"maxItems":@8,
                @"items":@{@"oneOf":@[@{@"type":@"number"},@{@"type":@"string"}]},
                @"description":@"Known fixed-GPR arguments x0-x7, integer numbers or hex strings. A buffer descriptor replaces its matching pointer argument."};
        }
        if ([name isEqualToString:@"hook_method"])
            d[@"description"] = @"Observe an Objective-C method. Runtime-declared fixed GPR/object arguments support bounded packed-stack forwarding for post capture; float/aggregate/variadic/exception ABI is not supported. Configuration is validated before installation and immutable after publication. Events expose phase/callId/parentCallId/payload.";
        if ([name isEqualToString:@"hook_inline"])
            d[@"description"] = @"Observe a native function via Dobby at a verified runtime address or module/symbol. Entry-only is the default; post requires an explicit fixed-GPR abi declaration and supports bounded stack forwarding. No variadic, float/aggregate or exception-unwind post. Events expose phase/callId/parentCallId/payload. Hard inline removal is refused without thread quiescence; soft stop retains the patch until target restart. Check actual backend availability.";
        if ([name isEqualToString:@"hook_import"])
            d[@"description"] = @"Observe a resolvable executable imported C symbol via fishhook. Registration covers present/future images with a fixed resolved-symbol forwarding target; per-image interposer chains are not preserved and successful GOT coverage must be confirmed by hits and entry/leave events. Post requires an explicit fixed-GPR abi declaration. Configuration is immutable; only soft stop is supported. Missing/data/allocator/runtime symbols are rejected before registration.";
        if ([name isEqualToString:@"unhook"])
            d[@"description"] = @"Stop recording. hard=true restores an owned ObjC IMP; inline hard removal refuses without thread quiescence, leaving state unchanged. Import supports soft stop only. Retired slot configuration is never reused.";
        schema[@"properties"] = properties; d[@"inputSchema"] = schema; [tools addObject:d];
    }
    [tools addObject:@{@"name": @"get_call", @"description": @"Read a function invocation by structured call_id, pairing entry/leave and retained synchronous descendants. Reports missing retention and output limits; does not infer asynchronous/full native call graphs.",
        @"inputSchema": @{@"type": @"object", @"required": @[@"call_id"], @"properties": @{
            @"call_id": @{@"type": @"string"}, @"include_children": @{@"type": @"boolean"},
            @"limit": @{@"type": @"number", @"minimum": @1, @"maximum": @200},
            @"max_blob_bytes": @{@"type": @"number", @"minimum": @0, @"maximum": @8192},
            @"max_output_bytes": @{@"type": @"number", @"minimum": @4096, @"maximum": @2097152}}}}];
    [tools addObject:@{@"name": @"run_hook_selftest", @"description": @"Explicit native ABI/structured-event diagnostic on IDH-owned synthetic fixtures only. Optional fixed-C getpid import is soft-stopped and retained until target restart. Does not issue business requests or call a signing oracle.",
        @"inputSchema": @{@"type": @"object", @"required": @[@"process_generation"], @"properties": @{
            @"process_generation": @{@"type": @"string"}, @"include_c_import": @{@"type": @"boolean"},
            @"include_native_backends": @{@"type": @"boolean", @"description": @"Test linked Inline/QBDI using IDH-owned pure fixtures, including packed stack/PAC calls and QBDI instruction budget. Leaves a soft-stopped native patch until target restart."}}}}];
    [tools addObjectsFromArray:@[
        @{@"name":@"trace_live_arm",@"description":@"Arm one actual next invocation of an enabled Inline hook. Captures all GPR/SIMD/flags and executes the original once under QBDI on its original thread and App stack; no replay or pointer substitution. Requires known normal return; exceptions/longjmp are unsupported. Record budgets stop recording only; they never abort the App call. At most eight retained sessions until restart.",
          @"inputSchema":@{@"type":@"object",@"required":@[@"process_generation",@"slot",@"normal_return"],@"properties":@{
            @"process_generation":@{@"type":@"string"},@"slot":@{@"type":@"integer",@"minimum":@0,@"maximum":@255},
            @"normal_return":@{@"type":@"boolean"},@"max_insns":@{@"type":@"integer",@"minimum":@1,@"maximum":@8192},
            @"max_ms":@{@"type":@"integer",@"minimum":@1,@"maximum":@10000},@"thread_id":@{@"type":@"string"}}}},
        @{@"name":@"trace_live_read",@"description":@"Read pending/completed actual-call trace and bounded instruction pages, entry/exit CPU, original stack bytes, synchronous unwind and recording truncation. Does not execute the target. Native execution outside the target module is counted as opaque transfers.",
          @"inputSchema":@{@"type":@"object",@"required":@[@"trace_id"],@"properties":@{@"trace_id":@{@"type":@"string"},@"offset":@{@"type":@"integer",@"minimum":@0},@"limit":@{@"type":@"integer",@"minimum":@1,@"maximum":@256}}}},
        @{@"name":@"trace_live_cancel",@"description":@"Cancel an armed capture before a real call claims it. Never cancels an executing App function. Inline patch remains until target restart.",
          @"inputSchema":@{@"type":@"object",@"required":@[@"process_generation",@"trace_id"],@"properties":@{@"process_generation":@{@"type":@"string"},@"trace_id":@{@"type":@"string"}}}},
        @{@"name":@"run_live_selftest",@"description":@"Explicit IDH-owned live-call, exactly-once side effect, packed stack, SIMD, scratch registers, recording budget and unwind fixture tests. No business signing oracle. Restart target afterward.",
          @"inputSchema":@{@"type":@"object",@"required":@[@"process_generation"],@"properties":@{@"process_generation":@{@"type":@"string"}}}}
    ]];
    [tools addObjectsFromArray:@[
      @{@"name":@"get_flow_diagnostics",@"description":@"Read a bounded ring of uncertain stack boundaries with precise stop reason and last native PC/SP/FP. CandidateTaskId is diagnostic only, not an established parent. Raw stacks are resolved on this reader thread.",@"inputSchema":@{@"type":@"object",@"properties":@{@"offset":@{@"type":@"integer",@"minimum":@0,@"maximum":@16},@"limit":@{@"type":@"integer",@"minimum":@1,@"maximum":@4}}}},
      @{@"name":@"configure_async_capture",@"description":@"Opt-in bounded GCD submit/execute correlation. Six public async/after/group submission imports plus two public block constructors. Selected first submissions of blocks created during capture preserve their original outer metadata and track the inner callback; reused-before-start is unresolved. Preexisting/unknown blocks pass through. Existing pending work keeps its identity after capture is disabled. No Swift/NSOperation/private scheduler coverage. Restart clears retained forwarding patches.",@"inputSchema":@{@"type":@"object",@"required":@[@"process_generation",@"enabled"],@"properties":@{@"process_generation":@{@"type":@"string"},@"enabled":@{@"type":@"boolean"},@"capture_roots":@{@"type":@"boolean"},@"queue_exclude":@{@"type":@"array",@"maxItems":@8,@"items":@{@"type":@"string"}},@"root_queue_include":@{@"type":@"array",@"maxItems":@8,@"items":@{@"type":@"string"}},@"max_tasks":@{@"type":@"integer",@"minimum":@1,@"maximum":@256},@"max_ms":@{@"type":@"integer",@"minimum":@1,@"maximum":@60000}}}},
      @{@"name":@"get_async_tasks",@"description":@"Read bounded observed GCD causal edges, submitter call/task and execution TID. Async edges are separate from native stacks and synchronous parentCallId. Pending is not completion; no guessed edges.",@"inputSchema":@{@"type":@"object",@"properties":@{@"task_id":@{@"type":@"string"},@"offset":@{@"type":@"integer",@"minimum":@0,@"maximum":@1024},@"limit":@{@"type":@"integer",@"minimum":@1,@"maximum":@128}}}},
      @{@"name":@"get_flow_state",@"description":@"Read bounded async and nonlocal-exit protection counters. Thread-local counters refer to the handling thread; no arbitrary thread state mutation.",@"inputSchema":@{@"type":@"object",@"properties":@{}}},
      @{@"name":@"run_flow_selftest",@"description":@"Explicit IDH-owned exception/longjmp cleanup, caught exception, GCD context propagation, bounded budget and worker-reuse fixtures. Does not run business signing functions; restart target after testing.",@"inputSchema":@{@"type":@"object",@"required":@[@"process_generation"],@"properties":@{@"process_generation":@{@"type":@"string"}}}}
    ]];
    return tools;
}

// ============================================================
// get_capture_coverage —— 「为什么抓不到」自检
//
// 逐层检查本进程的导入表: 符号出现在任何镜像的导入表里 → fishhook 可拦截(该层可用);
// 全都没有 → 该层要么没被这个 App 用, 要么已被静态链接进二进制(不可 hook)。
// 这正是分析 B站/中国移动时反复要手工试的事情, 固化成一条工具调用。
// ObjC 层(NSURLSession/NSURLConnection)不看导入表, 运行时 swizzle 恒可用。
// ============================================================
static NSDictionary *tool_get_capture_coverage(NSDictionary *args) {
    (void)args;
    NSArray *items = @[
        @[@"NSURLSession (ObjC)", @"", @"运行时 swizzle, 恒可用"],
        @[@"NSURLConnection (ObjC)", @"", @"运行时 swizzle, 恒可用"],
        @[@"OpenSSL/BoringSSL TLS", @"SSL_write", @"App 自带 TLS 才走这里"],
        @[@"OpenSSL/BoringSSL TLS", @"SSL_write_ex", @""],
        @[@"Apple SecureTransport", @"SSLWrite", @"Apple 命名无下划线: SSLWrite/SSLRead"],
        @[@"Apple SecureTransport", @"SSLRead", @""],
        @[@"BSD socket", @"socket", @"fd 生命周期跟踪"],
        @[@"BSD socket", @"accept", @"服务端连接登记"],
        @[@"BSD socket", @"connect", @"自研网络栈入口(可拿 ip:port)"],
        @[@"BSD socket", @"send", @"TLS 密文; 仅能解 ClientHello SNI"],
        @[@"BSD socket", @"sendto", @""],
        @[@"BSD socket", @"sendmsg", @""],
        @[@"BSD socket", @"recv", @""],
        @[@"BSD socket", @"recvfrom", @""],
        @[@"BSD socket", @"recvmsg", @""],
        @[@"BSD socket", @"read", @"仅对已跟踪 socket fd 记录"],
        @[@"BSD socket", @"write", @"仅对已跟踪 socket fd 记录"],
        @[@"BSD socket", @"getaddrinfo", @"域名解析"],
        @[@"Network.framework", @"nw_connection_send", @"NW 栈的明文入口"],
        @[@"Network.framework", @"nw_connection_receive", @"NW 栈的明文接收"],
        @[@"WebSocket (ObjC)", @"", @"NSURLSessionWebSocketTask 真实子类 send/recv/ping"],
        @[@"WebKit (ObjC)", @"", @"宿主侧 WKWebView 导航/JS bridge/Cookie/Scheme；不含 WebContent/Networking 进程"],
        @[@"Security RSA (modern)", @"SecKeyCreateEncryptedData", @""],
        @[@"Security RSA (legacy)", @"SecKeyEncrypt", @""],
        @[@"OpenSSL RSA", @"RSA_public_encrypt", @"静态链接时不可 hook"],
        @[@"OpenSSL RSA", @"EVP_PKEY_encrypt", @""],
        @[@"CommonCrypto", @"CCCrypt", @"对称加密(AES/DES)"],
        @[@"CommonCrypto RNG", @"CCRandomGenerateBytes", @"随机数(RSA 填充常用)"],
        @[@"Security RNG", @"SecRandomCopyBytes", @""],
    ];
    int imageCount = dh_symtab_image_count();
    NSMutableArray *rows = [NSMutableArray array];
    NSMutableDictionary *layerAvail = [NSMutableDictionary dictionary];
    for (NSArray *item in items) {
        NSString *layer = item[0], *sym = item[1], *hint = item[2];
        BOOL available = YES;
        int images = 0;
        if (sym.length) {
            for (int i = 0; i < imageCount; i++) {
                if (dh_symtab_imports(i, sym.UTF8String, 0, NULL, NULL) > 0) {
                    images++;
                    if (images >= 3) break;   // 只需判断可用性, 找到几处即可提前收工(全量扫描会很慢)
                }
            }
            available = images > 0;
        }
        NSNumber *prev = layerAvail[layer];
        layerAvail[layer] = (prev && ![prev boolValue]) ? @(available) : @(prev ? YES : available);
        [rows addObject:@{@"layer": layer,
                          @"symbol": sym.length ? sym : @"(runtime swizzle)",
                          @"available": available ? @YES : @NO,
                          @"images_importing": @(images),
                          @"hint": hint}];
    }
    NSMutableArray *blind = [NSMutableArray array];
    for (NSString *layer in layerAvail) if (![layerAvail[layer] boolValue]) [blind addObject:layer];
    return tool_ok(@{
        @"images_scanned": @(imageCount),
        @"layers": rows,
        @"blind_spots": blind,
        @"note": @"available=YES: 符号出现在某镜像导入表, fishhook 可拦截; 它只表示候选可用, 不代表当前请求一定经过该层。NO: 未被本 App 使用或已静态链接(不可 hook) —— 后者只能改走其调用层的 ObjC/Swift 入口取证。",
    });
}

static NSDictionary *tool_get_webkit_probe(NSDictionary *args) {
    (void)args;
    return tool_ok(dh_webkit_probe_snapshot());
}

static NSDictionary *tool_set_webkit_probe(NSDictionary *args) {
    if (![args isKindOfClass:[NSDictionary class]]) return tool_err(@"missing arguments");
    NSMutableDictionary *changes = [NSMutableDictionary dictionary];
    if (args[@"enabled"] != nil) changes[@"enabled"] = [args[@"enabled"] boolValue] ? @YES : @NO;
    if (args[@"redact"] != nil)  changes[@"redact"]  = [args[@"redact"] boolValue] ? @YES : @NO;
    for (NSString *field in @[@"allow", @"deny"]) {
        id value = args[field];
        if (![value isKindOfClass:[NSArray class]]) continue;
        NSMutableArray<NSString *> *items = [NSMutableArray array];
        for (id item in value)
            if ([item isKindOfClass:[NSString class]] && [item length])
                [items addObject:item];
        changes[field] = items;
    }
    if (!changes.count) return tool_err(@"missing one of: enabled, redact, allow, deny");
    dh_webkit_probe_set_config(changes);
    return tool_ok(dh_webkit_probe_snapshot());
}

static NSDictionary *dispatch_tool(NSString *name, NSDictionary *args) {
    if([@[@"configure_async_capture",@"run_flow_selftest"] containsObject:name] && ![args[@"process_generation"] isEqual:DHProcessGeneration()])return tool_err(@"missing or stale process_generation");
    if([name isEqual:@"get_flow_state"])return tool_ok(DHFlowState());
    if([name isEqual:@"run_flow_selftest"])return tool_ok(DHFlowSelfTest());
    if([name isEqual:@"configure_async_capture"] || [name isEqual:@"get_async_tasks"] || [name isEqual:@"get_flow_diagnostics"]) {
        for(NSString *key in @[@"enabled",@"capture_roots"])if(args[key] && (![args[key] isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)args[key])!=CFBooleanGetTypeID()))return tool_err(@"flow switches must be booleans");
        for(NSString *key in @[@"offset",@"limit",@"max_tasks",@"max_ms"])if(args[key] && (![args[key] isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)args[key])==CFBooleanGetTypeID() || !isfinite([args[key] doubleValue]) || [args[key] doubleValue]!=floor([args[key] doubleValue]) || [args[key] doubleValue]<0 || [args[key] doubleValue]>60000))return tool_err(@"flow bounds must be finite nonnegative integers");
        if([name isEqual:@"get_flow_diagnostics"]) {
            unsigned offset=[args[@"offset"] unsignedIntValue],limit=args[@"limit"]?[args[@"limit"] unsignedIntValue]:1;
            if(offset>16 || !limit || limit>4)return tool_err(@"diagnostic page out of range");
            return tool_ok(DHFlowDiagnostics(offset,limit));
        }
        if([name isEqual:@"configure_async_capture"]) {
            if(!args[@"enabled"])return tool_err(@"enabled is required");
            unsigned budget=args[@"max_tasks"]?[args[@"max_tasks"] unsignedIntValue]:128,ms=args[@"max_ms"]?[args[@"max_ms"] unsignedIntValue]:30000;
            if(!budget || budget>256 || !ms || ms>60000)return tool_err(@"async window out of range");
            NSDictionary *r=DHFlowConfigure([args[@"enabled"] boolValue],[args[@"capture_roots"] boolValue],budget,ms,args[@"queue_exclude"],args[@"root_queue_include"]);return [r[@"ok"] boolValue]?tool_ok(r):tool_err(r[@"error"]);
        }
        unsigned offset=[args[@"offset"] unsignedIntValue],limit=args[@"limit"]?[args[@"limit"] unsignedIntValue]:32;uint64_t task=0;
        if(offset>1024 || !limit || limit>128)return tool_err(@"async page out of range");
        if(args[@"task_id"]) {
            NSString *prefix=[DHProcessGeneration() stringByAppendingString:@":async:"];id value=args[@"task_id"];
            if(![value isKindOfClass:NSString.class] || ![value hasPrefix:prefix])return tool_err(@"unknown task generation");
            const char *number=[[value substringFromIndex:prefix.length] UTF8String];char *end=NULL;task=strtoull(number,&end,10);
            if(!number[0] || *end || task<1 || task>1024)return tool_err(@"invalid task id");
        }
        return tool_ok(DHFlowRead(offset,limit,task));
    }
    if ([@[@"hook_method", @"hook_inline", @"hook_import", @"unhook", @"trace_function", @"objc_call", @"run_hook_selftest", @"trace_live_arm", @"trace_live_cancel", @"run_live_selftest"] containsObject:name]) {
        NSString *generation = args[@"process_generation"];
        if (![generation isKindOfClass:NSString.class] || ![generation isEqualToString:DHProcessGeneration()])
            return tool_err(@"missing or stale process_generation; fetch get_capabilities and re-resolve the target before mutation");
    }
    if ([name isEqualToString:@"trace_live_arm"]) {
        id normal=args[@"normal_return"];
        if (![normal isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)normal)!=CFBooleanGetTypeID() || ![normal boolValue])
            return tool_err(@"normal_return:true must explicitly assert a known normally returning target");
        for (NSString *key in @[@"slot",@"max_insns",@"max_ms"])
            if (args[key] && (![args[key] isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)args[key])==CFBooleanGetTypeID() || !isfinite([args[key] doubleValue]) || [args[key] doubleValue]!=floor([args[key] doubleValue])))
                return tool_err(@"slot and budgets must be finite integers");
        if ([args[@"slot"] doubleValue]<0 || [args[@"slot"] doubleValue]>255 ||
            (args[@"max_insns"] && ([args[@"max_insns"] doubleValue]<1 || [args[@"max_insns"] doubleValue]>8192)) ||
            (args[@"max_ms"] && ([args[@"max_ms"] doubleValue]<1 || [args[@"max_ms"] doubleValue]>10000))) return tool_err(@"slot or live budget out of range");
        NSInteger slot=[args[@"slot"] integerValue];uint64_t target=0,original=0,thread=0;
        if (!args[@"slot"] || !dh_thunk_live_target((int)slot,&target,&original)) return tool_err(@"slot must be an enabled Inline hook in this process");
        if (args[@"thread_id"] && (![args[@"thread_id"] isKindOfClass:NSString.class] || !dh_parse_addr_arg(args[@"thread_id"],&thread))) return tool_err(@"invalid thread_id");
        NSDictionary *r=DHLiveArm((int)slot,target,original,args[@"max_insns"]?[args[@"max_insns"] unsignedIntValue]:4096,args[@"max_ms"]?[args[@"max_ms"] unsignedIntValue]:5000,thread);
        return [r[@"ok"] boolValue]?tool_ok(r):tool_err(r[@"error"]);
    }
    if ([name isEqualToString:@"trace_live_read"] || [name isEqualToString:@"trace_live_cancel"]) {
        if (![args[@"trace_id"] isKindOfClass:NSString.class]) return tool_err(@"trace_id must be a string");
        for (NSString *key in @[@"offset",@"limit"])
            if (args[key] && (![args[key] isKindOfClass:NSNumber.class] || !isfinite([args[key] doubleValue]) || [args[key] doubleValue]!=floor([args[key] doubleValue]) || CFGetTypeID((__bridge CFTypeRef)args[key])==CFBooleanGetTypeID() || [args[key] doubleValue]<0 || [args[key] doubleValue]>8192)) return tool_err(@"invalid page bounds");
        if (args[@"limit"] && ([args[@"limit"] integerValue]<1 || [args[@"limit"] integerValue]>256)) return tool_err(@"limit must be 1..256");
        NSDictionary *r=[name isEqualToString:@"trace_live_cancel"]?DHLiveCancel(args[@"trace_id"]):DHLiveRead(args[@"trace_id"],[args[@"offset"] unsignedIntValue],args[@"limit"]?[args[@"limit"] unsignedIntValue]:64);
        return [r[@"ok"] boolValue]?tool_ok(r):tool_err(r[@"error"]);
    }
    if ([name isEqualToString:@"run_live_selftest"]) return tool_ok(DHLiveBackendSelfTest());
    if ([name isEqualToString:@"get_call"]) return tool_get_call(args);
    if ([name isEqualToString:@"run_hook_selftest"]) {
        id flag = args[@"include_c_import"];
        if (flag && (![flag isKindOfClass:NSNumber.class] || ([flag doubleValue] != 0 && [flag doubleValue] != 1)))
            return tool_err(@"include_c_import must be a boolean");
        id native = args[@"include_native_backends"];
        if (native && (![native isKindOfClass:NSNumber.class] || ([native doubleValue] != 0 && [native doubleValue] != 1)))
            return tool_err(@"include_native_backends must be a boolean");
        NSMutableDictionary *result = [DHHookSelfTest([flag boolValue]) mutableCopy];
        if ([native boolValue] && [result[@"pass"] boolValue]) {
            result[@"nativeBackends"] = DHNativeBackendSelfTest();
            result[@"pass"] = result[@"nativeBackends"][@"pass"];
            if (![result[@"pass"] boolValue]) result[@"error"] = result[@"nativeBackends"][@"error"] ?: @"native backend self-test failed";
        }
        return tool_ok(result);
    }


    if ([name isEqualToString:@"get_capabilities"])      return tool_get_capabilities(args);
    if ([name isEqualToString:@"disassemble"])           return tool_disassemble(args);
    if ([name isEqualToString:@"analyze_function"])      return tool_analyze_function(args);
    if ([name isEqualToString:@"disassemble_function"])  return tool_disassemble_function(args);
    if ([name isEqualToString:@"resolve_symbol"])        return tool_resolve_symbol(args);
    if ([name isEqualToString:@"get_memory_mapping"])return tool_memory_mapping(args);
    if ([name isEqualToString:@"symbolicate"])           return tool_symbolicate(args);
    if ([name isEqualToString:@"objc_resolve_imp"])      return tool_objc_resolve_imp(args);
    if ([name isEqualToString:@"objc_dump_ivars"])       return tool_objc_dump_ivars(args);
    if ([name isEqualToString:@"objc_call"])             return tool_objc_call(args);
    if ([name isEqualToString:@"objc_export_data"])      return tool_objc_export_data(args);
    if ([name isEqualToString:@"find_objc_methods"])     return tool_find_objc_methods(args);
    if ([name isEqualToString:@"read_memory"])           return tool_read_memory(args);
    if ([name isEqualToString:@"search_memory"])         return tool_search_memory(args);
    if ([name isEqualToString:@"list_images"])           return tool_list_images(args);
    if ([name isEqualToString:@"list_loaded_images"])    return tool_list_loaded_images(args);
    if ([name isEqualToString:@"list_imports"])          return tool_list_imports(args);
    if ([name isEqualToString:@"get_macho_info"])        return tool_get_macho_info(args);
    if ([name isEqualToString:@"find_xrefs"])            return tool_find_xrefs(args);
    if ([name isEqualToString:@"find_string_refs"])      return tool_find_string_refs(args);
    if ([name isEqualToString:@"find_selector_refs"])    return tool_find_selector_refs(args);
    if ([name isEqualToString:@"find_function_refs"])    return tool_find_function_refs(args);
    if ([name isEqualToString:@"list_functions"])        return tool_list_functions(args);
    // 取证: 读
    if ([name isEqualToString:@"get_stats"])             return tool_get_stats(args);
    if ([name isEqualToString:@"query_events"])          return tool_query_events(args);
    if ([name isEqualToString:@"wait_events"])           return tool_wait_events(args);
    if ([name isEqualToString:@"agent_ping"])            return tool_agent_ping(args);
    if ([name isEqualToString:@"correlate_request"])     return tool_correlate_request(args);
    if ([name isEqualToString:@"get_event"])             return tool_get_event(args);
    if ([name isEqualToString:@"export_events"])         return tool_export_events(args);
    if ([name isEqualToString:@"query_noise"])           return tool_query_noise(args);
    if ([name isEqualToString:@"list_files"])            return tool_list_files(args);
    if ([name isEqualToString:@"read_file"])             return tool_read_file(args);
    if ([name isEqualToString:@"dump_status"])           return tool_dump_status(args);
    // 取证: 控制 (有副作用)
    if ([name isEqualToString:@"set_capture"])           return tool_set_capture(args);
    if ([name isEqualToString:@"set_pause"])             return tool_set_pause(args);
    if ([name isEqualToString:@"clear_events"])          return tool_clear_events(args);
    if ([name isEqualToString:@"start_dump"])            return tool_start_dump(args);
    // 配置面: 改机 / 噪声规则 / 日志配置 / 审查日志
    if ([name isEqualToString:@"get_spoof"])             return tool_get_spoof(args);
    if ([name isEqualToString:@"set_spoof"])             return tool_set_spoof(args);
    if ([name isEqualToString:@"get_noise_config"])      return tool_get_noise_config(args);
    if ([name isEqualToString:@"set_noise_config"])      return tool_set_noise_config(args);
    if ([name isEqualToString:@"clear_noise"])           return tool_clear_noise(args);
    if ([name isEqualToString:@"get_config"])            return tool_get_config(args);
    if ([name isEqualToString:@"set_config"])            return tool_set_config(args);
    if ([name isEqualToString:@"get_diag"])              return tool_get_diag(args);
    if ([name isEqualToString:@"get_capture_coverage"])  return tool_get_capture_coverage(args);
    if ([name isEqualToString:@"get_webkit_probe"])      return tool_get_webkit_probe(args);
    if ([name isEqualToString:@"set_webkit_probe"])      return tool_set_webkit_probe(args);
    // 动态 hook (一期: record-only)
    if ([name isEqualToString:@"hook_import"])           return tool_hook_import(args);
    if ([name isEqualToString:@"hook_method"])           return tool_hook_method(args);
    if ([name isEqualToString:@"hook_inline"])           return tool_hook_inline(args);
    if ([name isEqualToString:@"trace_function"])        return tool_trace_function(args);
    if ([name isEqualToString:@"list_hooks"])            return tool_list_hooks(args);
    if ([name isEqualToString:@"unhook"])                return tool_unhook(args);
    return nil;   // 未知工具
}

// ---- 重活串行化 ----
// search_memory / find_*_refs / analyze_function 这类工具单次会读几十 MB 宿主内存并跑 Capstone,
// 而 HTTP worker 队列是并发的: AI 客户端并发调用时会出现 N 份内存快照 + N 份 CPU 同时压在宿主
// App 上, 在 2~3GB 设备上足以把被注入进程顶到 jetsam/看门狗阈值(表现就是「App 无报告闪退」)。
// 这里把这类工具统一放到一条串行队列上执行, 单次只允许一个。
static BOOL tool_is_heavy(NSString *name) {
    static NSSet *heavy = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        heavy = [NSSet setWithArray:@[@"search_memory", @"find_xrefs", @"find_string_refs",
                                      @"find_selector_refs", @"find_function_refs",
                                      @"analyze_function", @"disassemble_function",
                                      @"find_objc_methods", @"export_events", @"start_dump",
                                      @"trace_function", @"run_hook_selftest", @"run_live_selftest", @"trace_live_arm", @"trace_live_cancel",@"configure_async_capture",@"run_flow_selftest"]];
    });
    return [heavy containsObject:name];
}

static NSDictionary *dispatch_tool_guarded(NSString *name, NSDictionary *args) {
    if (!tool_is_heavy(name)) return dispatch_tool(name, args);
    static dispatch_queue_t q = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        q = dispatch_queue_create("com.decrypthelper.mcp.heavy", DISPATCH_QUEUE_SERIAL);
    });
    // 审计: 重活工具的开始/结束都写进 diag。若宿主在扫描期间被杀, 日志里会留下「开始」但没有
    // 「完成」的那一条 —— 崩溃时间线可直接归因, 不必再靠猜。
    dh_diag_append(DH_DIAG_SYS, "INFO",
                   [[NSString stringWithFormat:@"heavy tool %@ 开始", name] UTF8String]);
    NSTimeInterval t0 = [NSDate timeIntervalSinceReferenceDate];
    __block NSDictionary *res = nil;
    dispatch_sync(q, ^{ res = dispatch_tool(name, args); });
    double ms = ([NSDate timeIntervalSinceReferenceDate] - t0) * 1000.0;
    dh_diag_append(DH_DIAG_SYS, "INFO",
                   [[NSString stringWithFormat:@"heavy tool %@ 完成 用时 %.0fms", name, ms] UTF8String]);
    return res;
}

// ============================================================
// MCP 协议分发
// ============================================================
@implementation MCPServer

+ (NSString *)sessionId {
    static NSString *sid = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ sid = [[NSUUID UUID] UUIDString]; });
    return sid;
}

+ (nullable NSDictionary *)handleMessage:(NSDictionary *)message {
    if (![message isKindOfClass:NSDictionary.class])
        return rpc_error(nil, -32600, @"Invalid Request");

    NSString *method = message[@"method"];
    id reqId = message[@"id"];                 // 缺失 => 通知
    BOOL isNotification = (reqId == nil);

    if (![method isKindOfClass:NSString.class]) {
        return isNotification ? nil : rpc_error(reqId, -32600, @"Invalid Request: missing method");
    }

    // ---- 通知 (无需应答) ----
    if (isNotification) {
        // notifications/initialized 等: 收下即可, 不回应答体。
        return nil;
    }

    NSDictionary *params = [message[@"params"] isKindOfClass:NSDictionary.class] ? message[@"params"] : @{};

    // ---- initialize ----
    if ([method isEqualToString:@"initialize"]) {
        NSString *reqProto = params[@"protocolVersion"];
        NSString *proto = ([reqProto isKindOfClass:NSString.class] &&
                           [mcp_supported_protocols() containsObject:reqProto])
                          ? reqProto : @MCP_DEFAULT_PROTO;
        return rpc_result(reqId, @{
            @"protocolVersion": proto,
            @"capabilities": @{@"tools": @{@"listChanged": @NO}},
            @"serverInfo": @{@"name": @MCP_SERVER_NAME, @"version": @MCP_SERVER_VERSION},
            @"instructions": @"iOS binary analysis tools: disassemble, analyze_function, list_imports, get_macho_info.",
        });
    }

    // ---- ping ----
    if ([method isEqualToString:@"ping"]) {
        return rpc_result(reqId, @{});
    }

    // ---- tools/list ----
    if ([method isEqualToString:@"tools/list"]) {
        return rpc_result(reqId, @{@"tools": tool_definitions()});
    }

    // ---- tools/call ----
    if ([method isEqualToString:@"tools/call"]) {
        NSString *name = params[@"name"];
        NSDictionary *args = [params[@"arguments"] isKindOfClass:NSDictionary.class] ? params[@"arguments"] : @{};
        if (![name isKindOfClass:NSString.class])
            return rpc_error(reqId, -32602, @"Invalid params: missing tool name");

        NSDictionary *toolResult = dispatch_tool_guarded(name, args);
        if (!toolResult)   // 未知工具名: 按 MCP 惯例走工具级错误信封, 而非协议错误
            return rpc_result(reqId, tool_err([NSString stringWithFormat:@"Unknown tool: %@", name]));
        return rpc_result(reqId, toolResult);
    }

    return rpc_error(reqId, -32601, [NSString stringWithFormat:@"Method not found: %@", method]);
}

@end
