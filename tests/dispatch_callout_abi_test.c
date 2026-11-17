#include "dh_dispatch_callout_abi.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    uint32_t arm64[8]={0xa9be4ff4,0xa9017bfd,0x910043fd,0xd63f0020,0xa9417bfd,0xa8c24ff4,0xd65f03c0,0};
    uint32_t arm64e[8]={0xd503237f,0xa9be4ff4,0xa9017bfd,0x910043fd,0xd63f083f,0xa9417bfd,0xa8c24ff4,0xd65f0fff};
    uint32_t compact[8]={0xd503237f,0xa9bf7bfd,0x910003fd,0xd63f083f,0xa8c17bfd,0xd65f0fff,0,0};
    assert(dh_dispatch_callout_prefix_valid(0x1000,0x103c,0x1010,arm64));
    assert(dh_dispatch_callout_prefix_valid(0x1000,0x1040,0x1014,arm64e));
    assert(dh_dispatch_callout_prefix_valid(0x1000,0x1018,0x1010,compact));
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x1010,0x1010,arm64));
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x103c,0x1014,arm64));
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x1020,0x1010,compact));
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x1084,0x1014,arm64e));
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x1040,0x1014,NULL));
    uint32_t bad[8];memcpy(bad,arm64e,sizeof(bad));bad[4]=0xd63f0000; // x0, not the actual function argument x1
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x1040,0x1014,bad));
    memcpy(bad,arm64e,sizeof(bad));bad[7]=0xd65f03c0; // PAC frame with unauthenticated return
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x1040,0x1014,bad));
    memcpy(bad,arm64,sizeof(bad));bad[2]=0xaa0003e1; // overwrites original x1
    assert(!dh_dispatch_callout_prefix_valid(0x1000,0x103c,0x1010,bad));
    puts("PASS actual A64/PAC callouts; reject truncated range, wrong callsite/register/return and argument overwrite");
    return 0;
}
