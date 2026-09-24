// dh_symtab.c — 见 dh_symtab.h。遍历 Mach-O 的 LC_SYMTAB, 取 undefined 符号 = 导入符号。
//
// 内存定位: 用 __LINKEDIT 段把文件偏移(symoff/stroff)换算成进程内地址:
//   linkedit_base = slide + __LINKEDIT.vmaddr - __LINKEDIT.fileoff
//   symtab = linkedit_base + symoff;  strtab = linkedit_base + stroff
// 这与 fishhook 内部定位符号表的方式一致, 因此这里「看得到的导入符号」正是它能 rebind 的集合。

#include "dh_symtab.h"
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <stdint.h>

static const char *basename_of(const char *p) {
    const char *b = p ? p : "";
    for (const char *s = b; *s; s++) if (*s == '/') b = s + 1;
    return b;
}

// 解析第 idx 个 image 的符号表位置。成功置出参并返回 1, 否则返回 0。
static int image_symtab(int idx,
                        const struct nlist_64 **symsOut, const char **strOut,
                        uint32_t *nsymsOut, uint32_t *strsizeOut, int *isMainOut) {
    if (isMainOut) *isMainOut = 0;
    if (idx < 0 || idx >= (int)_dyld_image_count()) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(idx);
    if (!mh || mh->magic != MH_MAGIC_64) return 0;
    if (isMainOut) *isMainOut = (mh->filetype == MH_EXECUTE) ? 1 : 0;
    intptr_t slide = _dyld_get_image_vmaddr_slide(idx);

    const struct symtab_command *sym = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const uint8_t *cmds = (const uint8_t *)mh + sizeof(struct mach_header_64);
    const uint8_t *end  = cmds + mh->sizeofcmds;   // 加载命令区上界, 防越界遍历
    const uint8_t *p = cmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (p + sizeof(struct load_command) > end) break;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command)) break;   // 含 cmdsize==0: 防死循环/越界
        if (p + lc->cmdsize > end) break;
        if (lc->cmd == LC_SYMTAB) {
            sym = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__LINKEDIT") == 0) linkedit = sg;
        }
        p += lc->cmdsize;
    }
    if (!sym || !linkedit) return 0;

    // symtab/strtab 必须整体落在 __LINKEDIT 的文件范围内, 否则按损坏处理放弃该 image
    // —— 否则下面用 base+symoff/stroff 直接读裸内存, 字段被污染会 OOB。
    uint64_t le_lo = linkedit->fileoff, le_hi = (uint64_t)linkedit->fileoff + linkedit->filesize;
    uint64_t sym_hi = (uint64_t)sym->symoff + (uint64_t)sym->nsyms * sizeof(struct nlist_64);
    uint64_t str_hi = (uint64_t)sym->stroff + (uint64_t)sym->strsize;
    if (sym->symoff < le_lo || sym_hi > le_hi) return 0;
    if (sym->stroff < le_lo || str_hi > le_hi) return 0;

    uintptr_t base = (uintptr_t)slide + (uintptr_t)linkedit->vmaddr - (uintptr_t)linkedit->fileoff;
    if (symsOut)    *symsOut    = (const struct nlist_64 *)(base + sym->symoff);
    if (strOut)     *strOut     = (const char *)(base + sym->stroff);
    if (nsymsOut)   *nsymsOut   = sym->nsyms;
    if (strsizeOut) *strsizeOut = sym->strsize;
    return 1;
}

// 是否为「导入(undefined external)」符号; 是则回填去过下划线的名字指针。
static int undef_name(const struct nlist_64 *s, const char *strtab, uint32_t strsize, const char **nameOut) {
    if (s->n_type & N_STAB) return 0;                 // 调试符号
    if (!(s->n_type & N_EXT)) return 0;               // 导入必为 external; 排除本地未定义符号
    if ((s->n_type & N_TYPE) != N_UNDF) return 0;     // 只要未定义(导入)
    uint32_t strx = s->n_un.n_strx;
    if (strx == 0 || strx >= strsize) return 0;
    const char *nm = strtab + strx;
    if (!nm[0]) return 0;
    if (nm[0] == '_') nm++;                            // 去前导下划线 = fishhook 用的名字
    if (!nm[0]) return 0;
    *nameOut = nm;
    return 1;
}

int dh_symtab_image_count(void) { return (int)_dyld_image_count(); }

void dh_symtab_image_name(int idx, char *buf, size_t buflen, int *isMain) {
    if (buf && buflen) buf[0] = '\0';
    if (isMain) *isMain = 0;
    if (idx < 0 || idx >= (int)_dyld_image_count()) return;
    const char *path = _dyld_get_image_name(idx);
    if (path && buf && buflen) { strncpy(buf, basename_of(path), buflen - 1); buf[buflen - 1] = '\0'; }
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(idx);
    if (mh && mh->magic == MH_MAGIC_64 && isMain) *isMain = (mh->filetype == MH_EXECUTE) ? 1 : 0;
}

int dh_symtab_imports(int idx, const char *q, int limit, dh_sym_cb cb, void *ctx) {
    const struct nlist_64 *st = NULL; const char *str = NULL; uint32_t nsyms = 0, strsize = 0;
    if (!image_symtab(idx, &st, &str, &nsyms, &strsize, NULL)) return 0;

    int matched = 0, called = 0;
    for (uint32_t i = 0; i < nsyms; i++) {
        const char *nm = NULL;
        if (!undef_name(&st[i], str, strsize, &nm)) continue;
        if (q && q[0] && !strstr(nm, q)) continue;
        matched++;
        if (cb && (limit <= 0 || called < limit)) { cb(nm, ctx); called++; }
    }
    return matched;
}
