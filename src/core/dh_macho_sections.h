#ifndef DH_MACHO_SECTIONS_H
#define DH_MACHO_SECTIONS_H

#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <stdint.h>
#include <string.h>

static inline int dh_macho_code_section(const char *name) {
    return !strcmp(name, "__text") || !strcmp(name, "__stubs") ||
           !strcmp(name, "__auth_stubs") || !strcmp(name, "__objc_stubs");
}

// 优先标准段；未找到时按权限、节名和所属段边界查找，不把自定义段名写死。
static inline const struct section_64 *dh_macho_find_section(
        const struct mach_header_64 *mh, const char *preferred, const char *name) {
    if (!mh || mh->magic != MH_MAGIC_64 || !preferred || !name) return NULL;
    const uint8_t *begin = (const uint8_t *)(mh + 1);
    const uint8_t *end = begin + mh->sizeofcmds;
    int required = dh_macho_code_section(name) ? VM_PROT_EXECUTE : VM_PROT_READ;
    for (int pass = 0; pass < 2; pass++) {
        const uint8_t *p = begin;
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            if ((size_t)(end - p) < sizeof(struct load_command)) return NULL;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end - p)) return NULL;
            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
                int same = strncmp(sg->segname, preferred, 16) == 0;
                if ((pass == 0 ? same : !same) && (sg->initprot & required) &&
                    sg->nsects <= (lc->cmdsize - sizeof(*sg)) / sizeof(struct section_64)) {
                    const struct section_64 *sections = (const struct section_64 *)(sg + 1);
                    for (uint32_t j = 0; j < sg->nsects; j++) {
                        const struct section_64 *s = &sections[j];
                        if (strncmp(s->sectname, name, 16) == 0 && s->size &&
                            s->addr >= sg->vmaddr && s->size <= sg->vmsize &&
                            s->addr - sg->vmaddr <= sg->vmsize - s->size)
                            return s;
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    return NULL;
}

// 段之间的 DATA/空洞不属于可执行范围，不能只用所有可执行段的 min/max 判断。
static inline int dh_macho_contains_exec(const struct mach_header_64 *mh,
                                          intptr_t slide, uint64_t address) {
    if (!mh || mh->magic != MH_MAGIC_64) return 0;
    const uint8_t *p = (const uint8_t *)(mh + 1), *end = p + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((size_t)(end - p) < sizeof(struct load_command)) return 0;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end - p)) return 0;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
            uint64_t start = sg->vmaddr + (uint64_t)slide;
            if ((sg->initprot & VM_PROT_EXECUTE) && address >= start && address - start < sg->vmsize)
                return 1;
        }
        p += lc->cmdsize;
    }
    return 0;
}

#endif
