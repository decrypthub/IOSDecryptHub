#ifndef DH_DISPATCH_CALLOUT_ABI_H
#define DH_DISPATCH_CALLOUT_ABI_H
#include <stdint.h>
#include <string.h>
static inline int dh_dispatch_callout_prefix_valid(uint64_t start,uint64_t end,uint64_t caller,const uint32_t words[8]) {
    if(!words || !start || end<=start || end-start>128)return 0;
    static const uint32_t plain[]={0xa9be4ff4,0xa9017bfd,0x910043fd,0xd63f0020,0xa9417bfd,0xa8c24ff4,0xd65f03c0};
    static const uint32_t pac[]={0xd503237f,0xa9be4ff4,0xa9017bfd,0x910043fd,0xd63f083f,0xa9417bfd,0xa8c24ff4,0xd65f0fff};
    static const uint32_t compactPAC[]={0xd503237f,0xa9bf7bfd,0x910003fd,0xd63f083f,0xa8c17bfd,0xd65f0fff};
    return (end-start>=sizeof(plain) && caller==start+16 && !memcmp(words,plain,sizeof(plain))) ||
        (end-start>=sizeof(pac) && caller==start+20 && !memcmp(words,pac,sizeof(pac))) ||
        (end-start==sizeof(compactPAC) && caller==start+16 && !memcmp(words,compactPAC,sizeof(compactPAC)));
}
#endif
