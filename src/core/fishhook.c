// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ---- IOSDecryptHub 扩展 ----
// 在经典 fishhook (间接符号表) 基础上增加:
//   1. LC_DYLD_CHAINED_FIXUPS 支持 (iOS 15+ / arm64e 新格式)
//   2. __AUTH_CONST 段扫描 (arm64e authenticated GOT)
//   3. arm64e Pointer Authentication 感知 (strip + re-sign)
//   4. hook 写入失败的能力报告 (dh_health)
// 仍然只改函数指针，不使用 inline hook，不违反架构边界。

#include "fishhook.h"
#include "dh_health.h"

#include <stdio.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fixup-chains.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

#ifndef SEG_AUTH_CONST
#define SEG_AUTH_CONST  "__AUTH_CONST"
#endif

// arm64e PAC helpers — 非 arm64e 编译时退化为 no-op
#if defined(__arm64e__)
#include <ptrauth.h>
#define DH_PAC_STRIP(ptr)       ptrauth_strip((ptr), ptrauth_key_asia)
#define DH_PAC_SIGN_DATA(ptr)   ptrauth_sign_unauthenticated((ptr), ptrauth_key_asia, 0)
#define DH_PAC_SIGN_DATA_D(ptr, div) \
    ptrauth_sign_unauthenticated((ptr), ptrauth_key_asia, (div))
#define DH_IS_ARM64E 1
#else
#define DH_PAC_STRIP(ptr)       (ptr)
#define DH_PAC_SIGN_DATA(ptr)   (ptr)
#define DH_PAC_SIGN_DATA_D(ptr, div) (ptr)
#define DH_IS_ARM64E 0
#endif

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

// ---------------------------------------------------------------------------
// 经典路径: 间接符号表 (传统 __DATA/__DATA_CONST GOT)
// ---------------------------------------------------------------------------

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {
        if (symbol_name_longer_than_1 &&
            strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
          if (cur->rebindings[j].replaced != NULL &&
              indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
          }
          kern_return_t err = vm_protect (mach_task_self (),
              (uintptr_t)indirect_symbol_bindings, section->size, 0,
              VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
          if (err == KERN_SUCCESS) {
            indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          } else {
            dh_health_hook_fail(DH_DIAG_GENERAL, cur->rebindings[j].name);
          }
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
}

// ---------------------------------------------------------------------------
// 新路径: LC_DYLD_CHAINED_FIXUPS (iOS 15+ / arm64e)
// ---------------------------------------------------------------------------

static bool safe_read_memory(const void *address, void *output, size_t size) {
  if (!address || !output || size == 0) return false;
  vm_size_t bytes_read = 0;
  kern_return_t result = vm_read_overwrite(
      mach_task_self(),
      (vm_address_t)(uintptr_t)address,
      (vm_size_t)size,
      (vm_address_t)(uintptr_t)output,
      &bytes_read);
  return result == KERN_SUCCESS && bytes_read == size;
}

// 从 imports 表中获取第 ordinal 个符号名
static const char *chained_import_symbol_name(
    const struct dyld_chained_fixups_header *hdr,
    uint32_t ordinal) {
  if (ordinal >= hdr->imports_count) return NULL;

  const uint8_t *base = (const uint8_t *)hdr;
  uint32_t name_offset = 0;

  switch (hdr->imports_format) {
    case DYLD_CHAINED_IMPORT: {
      const struct dyld_chained_import *imports =
          (const struct dyld_chained_import *)(base + hdr->imports_offset);
      name_offset = imports[ordinal].name_offset;
      break;
    }
    case DYLD_CHAINED_IMPORT_ADDEND: {
      const struct dyld_chained_import_addend *imports =
          (const struct dyld_chained_import_addend *)(base + hdr->imports_offset);
      name_offset = imports[ordinal].name_offset;
      break;
    }
    case DYLD_CHAINED_IMPORT_ADDEND64: {
      const struct dyld_chained_import_addend64 *imports =
          (const struct dyld_chained_import_addend64 *)(base + hdr->imports_offset);
      name_offset = imports[ordinal].name_offset;
      break;
    }
    default:
      return NULL;
  }

  return (const char *)(base + hdr->symbols_offset + name_offset);
}

// 在 rebindings 链表中查找匹配符号名 (带下划线前缀)
static struct rebinding *find_rebinding_for_symbol(
    struct rebindings_entry *rebindings,
    const char *symbol_name) {
  if (!symbol_name || symbol_name[0] != '_') return NULL;
  const char *bare = symbol_name + 1;  // 跳过 '_'
  struct rebindings_entry *cur = rebindings;
  while (cur) {
    for (size_t j = 0; j < cur->rebindings_nel; j++) {
      if (strcmp(bare, cur->rebindings[j].name) == 0) {
        return &cur->rebindings[j];
      }
    }
    cur = cur->next;
  }
  return NULL;
}

// 安全写入一个指针槽位 (vm_protect + 写入)
static bool safe_write_pointer(void **slot, void *new_value, size_t slot_size) {
  // 对齐到页边界
  uintptr_t page_start = (uintptr_t)slot & ~((uintptr_t)vm_page_size - 1);
  uintptr_t page_end = ((uintptr_t)slot + slot_size + vm_page_size - 1)
                       & ~((uintptr_t)vm_page_size - 1);
  vm_size_t region_size = page_end - page_start;

  kern_return_t err = vm_protect(mach_task_self(), page_start, region_size, 0,
                                 VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (err != KERN_SUCCESS) {
    return false;
  }
  *slot = new_value;
  return true;
}

// 遍历一个 segment 的 chained fixups 链，执行 rebinding
static void rebind_chained_segment(
    struct rebindings_entry *rebindings,
    const struct dyld_chained_fixups_header *hdr,
    const struct dyld_chained_starts_in_segment *seg_starts,
    uintptr_t segment_vm_addr,
    size_t segment_vm_size) {

  uint16_t pointer_format = seg_starts->pointer_format;
  uintptr_t segment_vm_end = 0;
  if (segment_vm_size < sizeof(uint64_t) ||
      __builtin_add_overflow(segment_vm_addr, segment_vm_size, &segment_vm_end)) {
    return;
  }

  for (uint16_t page_idx = 0; page_idx < seg_starts->page_count; page_idx++) {
    uint16_t page_start_offset = seg_starts->page_start[page_idx];
    if (page_start_offset == DYLD_CHAINED_PTR_START_NONE) {
      continue;
    }
    // 暂不处理 MULTI (极少见于用户态 dylib)
    if (page_start_offset & DYLD_CHAINED_PTR_START_MULTI) {
      continue;
    }

    // 链起始地址
    uintptr_t chain_addr = segment_vm_addr
                         + (uintptr_t)page_idx * seg_starts->page_size
                         + page_start_offset;
    if (chain_addr < segment_vm_addr ||
        chain_addr > segment_vm_end - sizeof(uint64_t)) {
      continue;
    }

    // 沿链遍历
    bool chain_end = false;
    while (!chain_end) {
      uint64_t raw = 0;
      if (!safe_read_memory((const void *)chain_addr, &raw, sizeof(raw))) {
        return;
      }

      // 根据 pointer_format 解析 bind/rebase 和 next
      uint32_t ordinal = 0;
      bool is_bind = false;
      uint16_t next_stride = 0;
      bool is_auth = false;
      uint16_t diversity = 0;
      uint8_t key = 0;

      switch (pointer_format) {
        case DYLD_CHAINED_PTR_64:
        case DYLD_CHAINED_PTR_64_OFFSET: {
          // 通用 64 位: bit63 = bind
          struct dyld_chained_ptr_64_bind bind_info;
          memcpy(&bind_info, &raw, sizeof(bind_info));
          is_bind = (raw >> 63) & 1;
          if (is_bind) {
            ordinal = bind_info.ordinal;
          }
          next_stride = bind_info.next * 4;
          break;
        }
        case DYLD_CHAINED_PTR_ARM64E:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24: {
          // arm64e: bit63 = auth, bit62 = bind
          is_auth = (raw >> 63) & 1;
          is_bind = (raw >> 62) & 1;
          if (is_bind) {
            if (is_auth) {
              if (pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                struct dyld_chained_ptr_arm64e_auth_bind24 ab24;
                memcpy(&ab24, &raw, sizeof(ab24));
                ordinal = ab24.ordinal;
                next_stride = ab24.next * 8;
                diversity = ab24.diversity;
                key = ab24.key;
              } else {
                struct dyld_chained_ptr_arm64e_auth_bind ab;
                memcpy(&ab, &raw, sizeof(ab));
                ordinal = ab.ordinal;
                next_stride = ab.next * 8;
                diversity = ab.diversity;
                key = ab.key;
              }
            } else {
              if (pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
                struct dyld_chained_ptr_arm64e_bind24 b24;
                memcpy(&b24, &raw, sizeof(b24));
                ordinal = b24.ordinal;
                next_stride = b24.next * 8;
              } else {
                struct dyld_chained_ptr_arm64e_bind b;
                memcpy(&b, &raw, sizeof(b));
                ordinal = b.ordinal;
                next_stride = b.next * 8;
              }
            }
          } else {
            // rebase — 提取 next
            if (is_auth) {
              struct dyld_chained_ptr_arm64e_auth_rebase ar;
              memcpy(&ar, &raw, sizeof(ar));
              next_stride = ar.next * 8;
            } else {
              struct dyld_chained_ptr_arm64e_rebase r;
              memcpy(&r, &raw, sizeof(r));
              next_stride = r.next * 8;
            }
          }
          break;
        }
        default:
          // 未知格式，跳过整个 segment
          return;
      }

      // 处理 bind 条目
      if (is_bind) {
        const char *sym_name = chained_import_symbol_name(hdr, ordinal);
        struct rebinding *rb = find_rebinding_for_symbol(rebindings, sym_name);
        if (rb) {
          void **slot = (void **)chain_addr;
          void *old_value = *slot;

          // 保存原始指针
          if (rb->replaced != NULL && old_value != rb->replacement) {
#if DH_IS_ARM64E
            *(rb->replaced) = DH_PAC_STRIP(old_value);
#else
            *(rb->replaced) = old_value;
#endif
          }

          // 根据认证状态签名替换指针
          void *new_value;
#if DH_IS_ARM64E
          if (is_auth) {
            // 使用与原始条目相同的 key 和 diversity 签名
            // key 0 = IA (Instruction A), 1 = IB, 2 = DA, 3 = DB
            // GOT 条目通常用 DA (key=2) 或 IA (key=0)
            if (key == 2) {
              new_value = ptrauth_sign_unauthenticated(
                  rb->replacement, ptrauth_key_asda, diversity);
            } else {
              new_value = ptrauth_sign_unauthenticated(
                  rb->replacement, ptrauth_key_asia, diversity);
            }
          } else {
            new_value = rb->replacement;
          }
#else
          (void)is_auth;
          (void)diversity;
          (void)key;
          new_value = rb->replacement;
#endif

          if (!safe_write_pointer(slot, new_value, sizeof(void *))) {
            dh_health_hook_fail(DH_DIAG_GENERAL, rb->name);
          }
        }
      }

      // 移动到链中下一个条目
      if (next_stride == 0) {
        chain_end = true;
      } else {
        uintptr_t next_addr = 0;
        if (__builtin_add_overflow(chain_addr, (uintptr_t)next_stride, &next_addr) ||
            next_addr < segment_vm_addr ||
            next_addr > segment_vm_end - sizeof(uint64_t)) {
          return;
        }
        chain_addr = next_addr;
      }
    }
  }
}

// 处理一个 image 的 LC_DYLD_CHAINED_FIXUPS
static bool rebind_symbols_with_chained_fixups(
    struct rebindings_entry *rebindings,
    const struct mach_header *header,
    intptr_t slide) {

  // 查找 LC_DYLD_CHAINED_FIXUPS
  const struct linkedit_data_command *chained_cmd = NULL;
  const segment_command_t *linkedit_seg = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds; i++) {
    const struct load_command *lc = (const struct load_command *)cur;
    if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
      chained_cmd = (const struct linkedit_data_command *)lc;
    } else if (lc->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      const segment_command_t *seg = (const segment_command_t *)lc;
      if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
        linkedit_seg = seg;
      }
    }
    cur += lc->cmdsize;
  }

  if (!chained_cmd || !linkedit_seg) {
    return false;  // 没有 chained fixups，回退到经典路径
  }

  // 计算 LINKEDIT 基地址
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_seg->vmaddr - linkedit_seg->fileoff;
  const struct dyld_chained_fixups_header *hdr =
      (const struct dyld_chained_fixups_header *)(linkedit_base + chained_cmd->dataoff);

  if (hdr->fixups_version != 0) {
    return false;
  }

  const struct dyld_chained_starts_in_image *starts =
      (const struct dyld_chained_starts_in_image *)
      ((const uint8_t *)hdr + hdr->starts_offset);

  // 构建 segment index → vm_addr 映射
  // chained fixups 的 seg_info_offset 按 segment 索引排列
  const segment_command_t *segments[64];
  uint32_t seg_count = 0;
  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds && seg_count < 64; i++) {
    const struct load_command *lc = (const struct load_command *)cur;
    if (lc->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      segments[seg_count++] = (const segment_command_t *)lc;
    }
    cur += lc->cmdsize;
  }

  // 遍历每个有 fixups 的 segment
  for (uint32_t seg_idx = 0; seg_idx < starts->seg_count && seg_idx < seg_count; seg_idx++) {
    uint32_t seg_info_off = starts->seg_info_offset[seg_idx];
    if (seg_info_off == 0) {
      continue;  // 该 segment 没有 fixups
    }

    const struct dyld_chained_starts_in_segment *seg_starts =
        (const struct dyld_chained_starts_in_segment *)
        ((const uint8_t *)starts + seg_info_off);

    const segment_command_t *segment = segments[seg_idx];
    uintptr_t segment_vm_addr = (uintptr_t)slide + segment->vmaddr;

    rebind_chained_segment(rebindings, hdr, seg_starts,
                           segment_vm_addr, (size_t)segment->vmsize);
  }

  return true;
}

// ---------------------------------------------------------------------------
// 入口: 对单个 image 执行 rebinding
// ---------------------------------------------------------------------------

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    fprintf(stderr, "[IOSDecryptHub/ERR] dladdr 失败, 跳过 image header=%p (该 image 的 hook 全部未生效)\n",
            (const void *)header);
    return;
  }

  // 优先尝试 chained fixups (iOS 15+ / arm64e 新格式)
  if (rebind_symbols_with_chained_fixups(rebindings, header, slide)) {
    // chained fixups 成功处理了该 image。
    // 注意: 即使有 chained fixups，某些 section 可能仍用间接符号表（混合情况极少，
    // 但为安全起见仍扫描传统 section）。
  }

  // 经典路径: 间接符号表 (兼容旧格式 + 混合情况)
  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

  // Find base symbol/string table addresses
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      // 扫描 __DATA, __DATA_CONST, __AUTH_CONST 三个段
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_AUTH_CONST) != 0) {
        continue;
      }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    if (rebindings_head) {
      free(rebindings_head->rebindings);
    }
    free(rebindings_head);
    return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }
  // If this was the first call, register callback for image additions (which is also invoked for
  // existing images, otherwise, just run on existing images
  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
