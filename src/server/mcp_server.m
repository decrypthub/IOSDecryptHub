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
#include "dh_health.h"
#include "dh_noise.h"
#include "dh_spoof.h"
#include "dh_files.h"
#include "dump_manager.h"
#include "hook_webkit.h"
#include <string.h>

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
            } else if (!target && op->type == AnalysisOperandImmediate && (n->is_jump || n->is_call)) {
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

    AnalysisInsn *insns = calloc(1024, sizeof(AnalysisInsn));
    if (!insns) return tool_err(@"out of memory");
    AnalysisAddressInfo info;
    BOOL haveFunction = analysis_address_info(addr, &info) == 0 && info.has_function &&
                        info.function_end > info.function_start;
    uint64_t readStart = haveFunction ? info.function_start : addr;
    size_t readSize = maxBytes;
    if (haveFunction && info.function_end - info.function_start < readSize)
        readSize = (size_t)(info.function_end - info.function_start);

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
        @"resolved_start": [NSString stringWithFormat:@"0x%llx", readStart],
        @"requested_offset": @(addr - readStart),
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

static BOOL objc_name_matches(NSString *value, NSString *query, NSString *mode) {
    if (!query.length) return YES;
    if ([mode isEqualToString:@"exact"]) return [value isEqualToString:query];
    if ([mode isEqualToString:@"prefix"]) return [value hasPrefix:query];
    return [value rangeOfString:query].location != NSNotFound;
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
        int aborted = 0;
        const char *cn = dh_safe_class_getName(cls, &aborted);
        if (aborted) { skippedLazyNames++; continue; }
        if (!cn) continue;
        NSString *className = @(cn);
        if (classNeedle.length &&
            [className.lowercaseString rangeOfString:classNeedle].location == NSNotFound) continue;
        const char *cip = class_getImageName(cls);
        NSString *classImage = cip ? @(cip) : @"";
        if (imageNeedle.length &&
            [classImage.lowercaseString rangeOfString:imageNeedle].location == NSNotFound) continue;
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
                NSString *selName = sel ? NSStringFromSelector(sel) : @"";
                if (!objc_name_matches(selName, selector, match)) continue;

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
    return tool_ok(@{
        @"pluginVersion":  @MCP_SERVER_VERSION,
        @"variant":        @(dh_variant_id(v)),
        @"variantLabel":   @(dh_variant_label(v)),
        @"arch":           @(dh_cpu_arch()),
        @"phase":          @"observe",   // 一期: 只观测; 二期: override(改写参数/返回值)
        @"capabilities":   @{
            @"hook_import":   (bits & DH_CAPBIT_HOOK_IMPORT)   ? @YES : @NO,  // fishhook GOT 改写
            @"hook_method":   (bits & DH_CAPBIT_HOOK_METHOD)   ? @YES : @NO,  // ObjC swizzle
            @"unpack":        (bits & DH_CAPBIT_UNPACK)        ? @YES : @NO,   // 脱壳
        },
        @"capabilityBits": @(bits),
        @"process":        [[DHLogStore shared] processInfo] ?: @{},
        // 本变体暴露的动态 hook 工具名。一期尚未实现动态 hook, 故为空; 二期按能力位填充。
        @"dynamicHookTools": @[],
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

// hook_import — 对导入 C 符号装只读 hook (fishhook GOT)。命中即记录参数寄存器快照+调用栈, 再透明转发。
static NSDictionary *tool_hook_import(NSDictionary *args) {
    NSString *sym = args[@"symbol"];
    if (![sym isKindOfClass:NSString.class] || sym.length == 0) return tool_err(@"symbol required");
    NSString *label = [args[@"label"] isKindOfClass:NSString.class] ? args[@"label"] : nil;
    int capPtr = -1, capLen = -1, capMax = 0;
    NSString *capErr = nil;
    if (!dh_parse_capture_memory(args, &capPtr, &capLen, &capMax, &capErr)) return tool_err(capErr);
    int slot = dh_thunk_install_import(sym.UTF8String, label.UTF8String);
    if (slot == -1) return tool_err(@"thunk slots exhausted (max 128)");
    if (slot == -2) return tool_err([NSString stringWithFormat:
        @"symbol '%@' not found in any image's import table — it is statically linked or not imported, so fishhook cannot rebind it. Try list_imports to confirm the symbol is an external import.", sym]);
    BOOL describe = [args[@"describe_args"] boolValue];
    if (describe && dh_thunk_set_describe(slot, 1) != 0) describe = NO;
    if (capPtr >= 0 && dh_thunk_set_capture(slot, capPtr, capLen, capMax) != 0) {
        dh_thunk_disable(slot);
        return tool_err(@"capture_memory 应用失败");
    }
    NSMutableDictionary *res = [@{@"slot": @(slot), @"symbol": sym, @"kind": @"import", @"enabled": @YES,
                                  @"describe_args": describe ? @YES : @NO,
                                  @"note": describe
                                    ? @"record-only + C 字符串参数反引用(前 4 个参数里像可打印字符串的会被记内容); events land in category 'other' as algorithm 'import-hook'."
                                    : @"record-only; events land in category 'other' as algorithm 'import-hook'. 传 describe_args:true 可尝试记录字符串参数(如 getaddrinfo 域名/dlopen 路径)。"} mutableCopy];
    NSDictionary *capEcho = dh_capture_echo(capPtr, capLen, capMax);
    if (capEcho) {
        res[@"capture"] = capEcho;
        res[@"note"] = [NSString stringWithFormat:@"%@ capture_memory: 命中瞬间把 arg%d 指向的内存(长度取自 arg%d%@, 上限 %d 字节)拷进事件 input。",
                        res[@"note"], capPtr, capLen, capLen < 0 ? @"(未指定, 用固定上限)" : @"", capMax];
    }
    return tool_ok(res);
}

// hook_method — 对 ObjC 方法装只读 hook (method_setImplementation swizzle)。同一套 thunk, x0=self x1=_cmd。
static NSDictionary *tool_hook_method(NSDictionary *args) {
    NSString *cls = args[@"class"];
    NSString *sel = args[@"selector"];
    if (![cls isKindOfClass:NSString.class] || cls.length == 0) return tool_err(@"class required");
    if (![sel isKindOfClass:NSString.class] || sel.length == 0) return tool_err(@"selector required");
    BOOL classMethod = [args[@"classMethod"] boolValue];
    int capPtr = -1, capLen = -1, capMax = 0;
    NSString *capErr = nil;
    if (!dh_parse_capture_memory(args, &capPtr, &capLen, &capMax, &capErr)) return tool_err(capErr);
    int slot = dh_thunk_install_method(cls.UTF8String, sel.UTF8String, classMethod ? 1 : 0);
    if (slot == -1) return tool_err(@"thunk slots exhausted (max 128)");
    if (slot == -3) return tool_err([NSString stringWithFormat:@"class '%@' or its %@ method '%@' not found",
                                     cls, classMethod ? @"class" : @"instance", sel]);
    BOOL describe = [args[@"describe_args"] boolValue];
    if (describe && dh_thunk_set_describe(slot, 1) != 0) describe = NO;
    if (capPtr >= 0 && dh_thunk_set_capture(slot, capPtr, capLen, capMax) != 0) {
        dh_thunk_disable(slot);
        return tool_err(@"capture_memory 应用失败");
    }
    NSMutableDictionary *res = [@{@"slot": @(slot),
                                  @"target": [NSString stringWithFormat:@"%@[%@ %@]", classMethod ? @"+" : @"-", cls, sel],
                                  @"kind": @"method", @"enabled": @YES,
                                  @"describe_args": describe ? @YES : @NO,
                                  @"note": describe
                                    ? @"record-only + 参数反引用(NSData→hex, NSString→文本, 其它→description); events land in category 'other' as algorithm 'objc-hook'."
                                    : @"record-only; events land in category 'other' as algorithm 'objc-hook'. 传 describe_args:true 可直接记录参数内容。"} mutableCopy];
    NSDictionary *capEcho = dh_capture_echo(capPtr, capLen, capMax);
    if (capEcho) {
        res[@"capture"] = capEcho;
        res[@"note"] = [NSString stringWithFormat:@"%@ capture_memory: 命中瞬间把 x%d 指向的内存(长度取自 x%d%@, 上限 %d 字节)拷进事件 input。",
                        res[@"note"], capPtr, capLen, capLen < 0 ? @"(未指定, 用固定上限)" : @"", capMax];
    }
    return tool_ok(res);
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
            @"kind":    info[i].kind == DH_HOOK_METHOD ? @"method" : @"import",
            @"name":    info[i].name ? @(info[i].name) : @"",
            @"hits":    @(info[i].hits),
            @"enabled": info[i].enabled ? @YES : @NO,
        } mutableCopy];
        NSDictionary *cap = dh_capture_echo(info[i].capture_ptr_arg, info[i].capture_len_arg,
                                            info[i].capture_max_bytes);
        if (cap) h[@"capture"] = cap;
        [arr addObject:h];
    }
    return tool_ok(@{@"count": @((NSInteger)arr.count), @"capacity": @(DH_THUNK_COUNT), @"hooks": arr});
}

// unhook — 原子关闭一个 hook (停止记录, thunk 仍透明转发, 槽位不回收)。
static NSDictionary *tool_unhook(NSDictionary *args) {
    NSNumber *slot = args[@"slot"];
    if (![slot isKindOfClass:NSNumber.class]) return tool_err(@"slot (number) required");
    int r = dh_thunk_disable(slot.intValue);
    if (r != 0) return tool_err([NSString stringWithFormat:@"slot %@ is not an active hook", slot]);
    return tool_ok(@{@"slot": slot, @"enabled": @NO,
                     @"note": @"recording stopped; the thunk keeps forwarding transparently (slot not reclaimed)."});
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
        if (!event_passes_extra(e, outHexEq, outHexPre, outLen, tid, sinceMs, untilMs, stackHas)) continue;
        matched++;
        if ((NSInteger)out.count < limit) [out addObject:dh_log_entry_summary(e)];
    }
    return tool_ok(@{@"count": @(out.count), @"matched": @(matched), @"events": out});
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
    return @[
        @{
            @"name": @"get_capabilities",
            @"description": @"Handshake — call FIRST. Returns plugin version, packaging variant (dev/trollstore), CPU arch, current phase (observe|override), and per-tier hook capability flags (hook_import/hook_method/unpack). Also returns guidance.whenNoCryptoEvents: when standard crypto hooks (CCCrypt/EVP/SecKey) show no events but network traffic is encrypted, enumerate pointer+length imports (mlock/memcpy/read/send/getrandom) and capture at call time with hook_import(capture_memory) instead of attempting unsupported hooks.",
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
            @"description": @"Disassemble the function containing `address` into structured instructions. When LC_FUNCTION_STARTS is available, an interior address is normalized to the real function start and decoding stops at the next function entry instead of the first ret. The response reports resolved_start/end, requested_offset, boundary_source/confidence and truncation. Falls back to a low-confidence ret heuristic only when function metadata is unavailable. ARM64 MOVZ/MOVN/MOVK constants are reconstructed only within the returned linear instruction stream.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"address": @{@"type": @"string", @"description": @"Function start address, e.g. \"0x1029ac000\""},
                    @"max_bytes": @{@"type": @"number", @"description": @"Read cap before forced stop (default 4096, max 65536)"},
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
                    @"describe_args": @{@"type": @"boolean", @"description": @"true 时尝试把前 4 个参数里「像可打印 C 字符串」的读出来(如 getaddrinfo 的域名、dlopen 的路径); 默认 false"},
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
            @"description": @"Install a record-only hook on an Objective-C method via method_setImplementation swizzle. On each call it snapshots self (x0), _cmd/SEL (x1), and arg registers, records an event (category 'other', algorithm 'objc-hook'), then forwards to the original IMP. Observe-only.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{
                    @"class":       @{@"type": @"string", @"description": @"ObjC class name, e.g. \"NSURLSession\""},
                    @"selector":    @{@"type": @"string", @"description": @"Selector, e.g. \"dataTaskWithRequest:completionHandler:\""},
                    @"classMethod": @{@"type": @"boolean", @"description": @"true for a class (+) method; default false (instance -)"},
                    @"describe_args": @{@"type": @"boolean", @"description": @"true 时反引用前几个参数内容(NSData→hex 前缀 / NSString→文本 / 其它→description), 直接看明文、密钥、密文; 默认 false"},
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
            @"name": @"list_hooks",
            @"description": @"List all dynamic hooks installed this session (slot, kind, name, hit count, enabled). Slots are not reclaimed; a disabled hook still shows with enabled=false.",
            @"inputSchema": @{@"type": @"object", @"properties": @{}},
        },
        @{
            @"name": @"unhook",
            @"description": @"Atomically disable a dynamic hook by slot (from hook_import/hook_method/list_hooks). Stops recording; the thunk keeps forwarding transparently so there is no unbind race.",
            @"inputSchema": @{
                @"type": @"object",
                @"properties": @{@"slot": @{@"type": @"number", @"description": @"Hook slot id"}},
                @"required": @[@"slot"],
            },
        },
    ];
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
    if ([name isEqualToString:@"get_capabilities"])      return tool_get_capabilities(args);
    if ([name isEqualToString:@"disassemble"])           return tool_disassemble(args);
    if ([name isEqualToString:@"analyze_function"])      return tool_analyze_function(args);
    if ([name isEqualToString:@"disassemble_function"])  return tool_disassemble_function(args);
    if ([name isEqualToString:@"resolve_symbol"])        return tool_resolve_symbol(args);
    if ([name isEqualToString:@"symbolicate"])           return tool_symbolicate(args);
    if ([name isEqualToString:@"objc_resolve_imp"])      return tool_objc_resolve_imp(args);
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
                                      @"find_objc_methods", @"export_events", @"start_dump"]];
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
