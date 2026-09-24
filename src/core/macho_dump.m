// macho_dump.m — 见 macho_dump.h
#import "macho_dump.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <mach/machine.h>
#import <libkern/OSByteOrder.h>
#import <stdio.h>
#import <sys/types.h>

@implementation DHDumpImage
@end

static NSError *dh_dump_err(NSString *msg) {
    return [NSError errorWithDomain:@"com.decrypthelper.dump"
                               code:-1
                           userInfo:@{NSLocalizedDescriptionKey: msg ?: @"未知错误"}];
}

// 在内存 header 里找 LC_ENCRYPTION_INFO_64, 返回是否找到, 并输出 off/size/id。
static BOOL find_encryption_info(const struct mach_header *mh,
                                 uint32_t *cryptoff, uint32_t *cryptsize, uint32_t *cryptid) {
    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) return NO;
    const uint8_t *cur = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmdsize == 0) break;
        if (lc->cmd == LC_ENCRYPTION_INFO_64) {
            const struct encryption_info_command_64 *ei =
                (const struct encryption_info_command_64 *)lc;
            if (cryptoff)  *cryptoff  = ei->cryptoff;
            if (cryptsize) *cryptsize = ei->cryptsize;
            if (cryptid)   *cryptid   = ei->cryptid;
            return YES;
        }
        cur += lc->cmdsize;
    }
    return NO;
}

NSArray<DHDumpImage *> *dh_dump_list_images(void) {
    NSMutableArray<DHDumpImage *> *out = [NSMutableArray array];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *execPath   = [[NSBundle mainBundle] executablePath];
    if (bundlePath.length == 0) return out;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *cname = _dyld_get_image_name(i);
        if (!cname) continue;
        NSString *path = [NSString stringWithUTF8String:cname];
        if (!path || ![path hasPrefix:bundlePath]) continue;   // 只看本 App bundle 内的镜像

        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) continue;   // 仅 64 位

        uint32_t cid = 0, csize = 0, coff = 0;
        find_encryption_info(mh, &coff, &csize, &cid);

        DHDumpImage *img = [DHDumpImage new];
        img.path      = path;
        img.name      = [path lastPathComponent];
        img.kind      = (execPath && [path isEqualToString:execPath]) ? @"main" : @"framework";
        img.cryptid   = cid;
        img.cryptsize = csize;
        img.header    = mh;
        [out addObject:img];
    }
    return out;
}

// 在磁盘文件里定位当前 cpu 对应的 thin slice (处理 FAT)。成功 YES 并输出 off/size。
static BOOL locate_slice(NSData *fileData, const struct mach_header *mh,
                         uint64_t *sliceOff, uint64_t *sliceSize, NSString **err) {
    *sliceOff = 0;
    *sliceSize = fileData.length;
    if (fileData.length < sizeof(uint32_t)) { if (err) *err = @"文件过小"; return NO; }

    const uint8_t *fb = (const uint8_t *)fileData.bytes;
    uint32_t magic = *(const uint32_t *)fb;

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        return YES;   // 已是 thin 64 位
    }
    if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        if (err) *err = @"暂不支持 fat_arch_64 容器";
        return NO;
    }
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        if (fileData.length < sizeof(struct fat_header)) { if (err) *err = @"FAT 头损坏"; return NO; }
        const struct fat_header *fh = (const struct fat_header *)fb;
        uint32_t narch = OSSwapBigToHostInt32(fh->nfat_arch);
        cpu_type_t    wantCpu = mh->cputype;
        cpu_subtype_t wantSub = mh->cpusubtype & ~CPU_SUBTYPE_MASK;

        if (fileData.length < sizeof(struct fat_header) + (uint64_t)narch * sizeof(struct fat_arch)) {
            if (err) *err = @"FAT arch 表越界"; return NO;
        }
        const struct fat_arch *fa = (const struct fat_arch *)(fb + sizeof(struct fat_header));

        // 优先精确匹配 cputype + cpusubtype, 否则退化为仅 cputype 匹配
        long fallback = -1;
        for (uint32_t a = 0; a < narch; a++) {
            cpu_type_t    cpu = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa[a].cputype);
            cpu_subtype_t sub = (cpu_subtype_t)(OSSwapBigToHostInt32((uint32_t)fa[a].cpusubtype) & ~CPU_SUBTYPE_MASK);
            if (cpu != wantCpu) continue;
            if (fallback < 0) fallback = a;
            if (sub == wantSub) {
                *sliceOff  = OSSwapBigToHostInt32(fa[a].offset);
                *sliceSize = OSSwapBigToHostInt32(fa[a].size);
                return YES;
            }
        }
        if (fallback >= 0) {
            *sliceOff  = OSSwapBigToHostInt32(fa[fallback].offset);
            *sliceSize = OSSwapBigToHostInt32(fa[fallback].size);
            return YES;
        }
        if (err) *err = @"FAT 中未找到当前架构 slice";
        return NO;
    }
    if (err) *err = @"未知的 Mach-O magic";
    return NO;
}

NSData *dh_dump_decrypt_image(DHDumpImage *img, NSError **error) {
    const struct mach_header *mh = img.header;
    if (!mh) { if (error) *error = dh_dump_err(@"镜像 header 为空"); return nil; }

    // 1. 内存里读取加密信息
    uint32_t cryptoff = 0, cryptsize = 0, cryptid = 0;
    BOOL hasEnc = find_encryption_info(mh, &cryptoff, &cryptsize, &cryptid);

    // 2. 读磁盘原文件
    NSError *rerr = nil;
    NSData *fileData = [NSData dataWithContentsOfFile:img.path options:0 error:&rerr];
    if (!fileData) {
        if (error) *error = dh_dump_err([NSString stringWithFormat:@"读取文件失败: %@", rerr.localizedDescription]);
        return nil;
    }

    // 3. 定位 thin slice
    uint64_t sliceOff = 0, sliceSize = 0;
    NSString *serr = nil;
    if (!locate_slice(fileData, mh, &sliceOff, &sliceSize, &serr)) {
        if (error) *error = dh_dump_err(serr ?: @"定位 slice 失败");
        return nil;
    }
    if (sliceOff + sliceSize > fileData.length) {
        if (error) *error = dh_dump_err(@"slice 范围越界");
        return nil;
    }

    // 4. 复制 thin slice 为可写副本
    NSMutableData *out = [NSMutableData dataWithBytes:((const uint8_t *)fileData.bytes + sliceOff)
                                              length:(NSUInteger)sliceSize];
    uint8_t *ob = (uint8_t *)out.mutableBytes;

    // 5. 用内存中已解密的数据覆盖加密段
    if (hasEnc && cryptid != 0 && cryptsize > 0) {
        if ((uint64_t)cryptoff + cryptsize > out.length) {
            if (error) *error = dh_dump_err(@"加密段范围超出 slice");
            return nil;
        }
        // cryptoff 是相对 thin Mach-O 文件起点的偏移; 内存中该 thin 镜像基址即 mh,
        // 故已解密数据位于 (uint8_t*)mh + cryptoff。
        const uint8_t *decrypted = (const uint8_t *)mh + cryptoff;
        memcpy(ob + cryptoff, decrypted, cryptsize);
    }

    // 6. 把副本里的 cryptid 改成 0
    if (hasEnc) {
        struct mach_header_64 *oh = (struct mach_header_64 *)ob;
        uint8_t *cur = ob + sizeof(struct mach_header_64);
        uint8_t *end = ob + out.length;
        for (uint32_t i = 0; i < oh->ncmds; i++) {
            if (cur + sizeof(struct load_command) > end) break;
            struct load_command *lc = (struct load_command *)cur;
            if (lc->cmdsize == 0) break;
            if (lc->cmd == LC_ENCRYPTION_INFO_64) {
                if (cur + sizeof(struct encryption_info_command_64) > end) break;
                struct encryption_info_command_64 *ei = (struct encryption_info_command_64 *)cur;
                ei->cryptid = 0;
                break;
            }
            cur += lc->cmdsize;
        }
    }

    return out;
}

// ============================================================
// 流式版 —— 见 macho_dump.h。不把镜像整体读进内存, 适合大主程序。
// ============================================================

// 在内存 header 里找 LC_ENCRYPTION_INFO_64; 额外输出 cryptid 字段相对 mh 的偏移
// (= 在 thin Mach-O 文件中的偏移, 用于 patch)。返回是否找到。
static BOOL find_encryption_info_ext(const struct mach_header *mh,
                                     uint32_t *cryptoff, uint32_t *cryptsize, uint32_t *cryptid,
                                     uint64_t *cryptidFieldOff) {
    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64) return NO;
    const uint8_t *cur = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmdsize == 0) break;
        if (lc->cmd == LC_ENCRYPTION_INFO_64) {
            const struct encryption_info_command_64 *ei = (const struct encryption_info_command_64 *)lc;
            if (cryptoff)  *cryptoff  = ei->cryptoff;
            if (cryptsize) *cryptsize = ei->cryptsize;
            if (cryptid)   *cryptid   = ei->cryptid;
            if (cryptidFieldOff)
                *cryptidFieldOff = (uint64_t)((const uint8_t *)&ei->cryptid - (const uint8_t *)mh);
            return YES;
        }
        cur += lc->cmdsize;
    }
    return NO;
}

// 流式定位 thin slice: 只读文件头(不载入整文件)。
static BOOL locate_slice_stream(FILE *in, off_t fileSize, const struct mach_header *mh,
                                uint64_t *sliceOff, uint64_t *sliceSize, NSString **err) {
    *sliceOff = 0;
    *sliceSize = (uint64_t)fileSize;
    uint8_t hdr[4096];
    if (fseeko(in, 0, SEEK_SET) != 0) { if (err) *err = @"seek 文件头失败"; return NO; }
    size_t got = fread(hdr, 1, sizeof(hdr), in);
    if (got < sizeof(uint32_t)) { if (err) *err = @"文件过小"; return NO; }

    uint32_t magic = *(const uint32_t *)hdr;
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) return YES;   // thin 64 位
    if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) { if (err) *err = @"暂不支持 fat_arch_64 容器"; return NO; }
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        const struct fat_header *fh = (const struct fat_header *)hdr;
        uint32_t narch = OSSwapBigToHostInt32(fh->nfat_arch);
        cpu_type_t    wantCpu = mh->cputype;
        cpu_subtype_t wantSub = mh->cpusubtype & ~CPU_SUBTYPE_MASK;
        if (sizeof(struct fat_header) + (uint64_t)narch * sizeof(struct fat_arch) > got) {
            if (err) *err = @"FAT arch 表超出头缓冲"; return NO;
        }
        const struct fat_arch *fa = (const struct fat_arch *)(hdr + sizeof(struct fat_header));
        long fallback = -1;
        for (uint32_t a = 0; a < narch; a++) {
            cpu_type_t    cpu = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa[a].cputype);
            cpu_subtype_t sub = (cpu_subtype_t)(OSSwapBigToHostInt32((uint32_t)fa[a].cpusubtype) & ~CPU_SUBTYPE_MASK);
            if (cpu != wantCpu) continue;
            if (fallback < 0) fallback = a;
            if (sub == wantSub) {
                *sliceOff  = OSSwapBigToHostInt32(fa[a].offset);
                *sliceSize = OSSwapBigToHostInt32(fa[a].size);
                return YES;
            }
        }
        if (fallback >= 0) {
            *sliceOff  = OSSwapBigToHostInt32(fa[fallback].offset);
            *sliceSize = OSSwapBigToHostInt32(fa[fallback].size);
            return YES;
        }
        if (err) *err = @"FAT 中未找到当前架构 slice"; return NO;
    }
    if (err) *err = @"未知的 Mach-O magic"; return NO;
}

// 从 in 流式复制 n 字节到 out (64KB 块)。
static BOOL stream_copy_n(FILE *in, FILE *out, uint64_t n, NSString **err) {
    uint8_t buf[64 * 1024];
    while (n > 0) {
        size_t want = n < sizeof(buf) ? (size_t)n : sizeof(buf);
        size_t got = fread(buf, 1, want, in);
        if (got == 0) { if (err) *err = @"读取原文件中断"; return NO; }
        if (fwrite(buf, 1, got, out) != got) { if (err) *err = @"写出失败"; return NO; }
        n -= got;
    }
    return YES;
}

BOOL dh_dump_decrypt_image_to_file(DHDumpImage *img, const char *outPath, NSError **error) {
    const struct mach_header *mh = img.header;
    if (!mh)      { if (error) *error = dh_dump_err(@"镜像 header 为空"); return NO; }
    if (!outPath) { if (error) *error = dh_dump_err(@"输出路径为空"); return NO; }

    uint32_t cryptoff = 0, cryptsize = 0, cryptid = 0;
    uint64_t cidFieldOff = 0;
    BOOL hasEnc = find_encryption_info_ext(mh, &cryptoff, &cryptsize, &cryptid, &cidFieldOff);

    FILE *in = fopen(img.path.fileSystemRepresentation, "rb");
    if (!in) { if (error) *error = dh_dump_err(@"打开原文件失败"); return NO; }

    if (fseeko(in, 0, SEEK_END) != 0) { fclose(in); if (error) *error = dh_dump_err(@"定位文件尾失败"); return NO; }
    off_t fsz = ftello(in);
    if (fsz <= 0) { fclose(in); if (error) *error = dh_dump_err(@"文件大小异常"); return NO; }

    uint64_t sliceOff = 0, sliceSize = 0;
    NSString *serr = nil;
    if (!locate_slice_stream(in, fsz, mh, &sliceOff, &sliceSize, &serr)) {
        fclose(in); if (error) *error = dh_dump_err(serr ?: @"定位 slice 失败"); return NO;
    }
    if (sliceOff + sliceSize > (uint64_t)fsz) {
        fclose(in); if (error) *error = dh_dump_err(@"slice 范围越界"); return NO;
    }
    BOOL doDecrypt = (hasEnc && cryptid != 0 && cryptsize > 0);
    if (doDecrypt && ((uint64_t)cryptoff + cryptsize > sliceSize)) {
        fclose(in); if (error) *error = dh_dump_err(@"加密段范围超出 slice"); return NO;
    }

    FILE *out = fopen(outPath, "wb");
    if (!out) { fclose(in); if (error) *error = dh_dump_err(@"创建输出文件失败"); return NO; }

    BOOL ok = YES;
    if (fseeko(in, (off_t)sliceOff, SEEK_SET) != 0) { ok = NO; serr = @"定位 slice 起点失败"; }

    if (ok && doDecrypt) {
        // 段1: 加密段之前 [0, cryptoff)
        ok = stream_copy_n(in, out, cryptoff, &serr);
        // 段2: 内存中已解密的 cryptsize 字节 (mh + cryptoff)
        if (ok && fwrite((const uint8_t *)mh + cryptoff, 1, cryptsize, out) != cryptsize) {
            ok = NO; serr = @"写入解密段失败";
        }
        // 段3: 跳过原文件加密部分, 复制剩余
        if (ok && fseeko(in, (off_t)(sliceOff + cryptoff + cryptsize), SEEK_SET) != 0) {
            ok = NO; serr = @"跳过加密段失败";
        }
        if (ok) ok = stream_copy_n(in, out, sliceSize - cryptoff - cryptsize, &serr);
    } else if (ok) {
        // cryptid==0 / 无加密: 整段流式复制 thin slice
        ok = stream_copy_n(in, out, sliceSize, &serr);
    }
    fclose(in);

    // patch cryptid -> 0 (字段落在加密段之前, 已写入 out, seek 回去改 4 字节)
    if (ok && hasEnc) {
        if (fseeko(out, (off_t)cidFieldOff, SEEK_SET) == 0) {
            uint32_t zero = 0;
            if (fwrite(&zero, 1, sizeof(zero), out) != sizeof(zero)) { ok = NO; serr = @"patch cryptid 失败"; }
        } else { ok = NO; serr = @"定位 cryptid 字段失败"; }
    }
    if (fclose(out) != 0 && ok) { ok = NO; serr = @"关闭输出文件失败"; }

    if (!ok) {
        remove(outPath);
        if (error) *error = dh_dump_err(serr ?: @"流式砸壳失败");
        return NO;
    }
    return YES;
}
