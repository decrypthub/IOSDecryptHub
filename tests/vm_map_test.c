#include "dh_vm_map.h"
#include <assert.h>
#include <stdio.h>

typedef struct {unsigned calls;int mode;uint64_t target;} Fixture;
static int query(void *opaque,uint64_t *address,uint64_t *length,unsigned *depth,DHVMRegion *step) {
    Fixture *f=opaque;assert(*address==f->target);assert(*depth==f->calls);f->calls++;
    if(f->mode==2)return 5;
    if(f->mode==3){*address=f->target+0x1000;*length=0x1000;return 0;}
    if(f->mode==4){*length=0;return 0;}
    *address=0x1000;*length=0x9000;step->isSubmap=1;
    if(f->mode==5)return 0;
    if(*depth==1){*address=0x3000;*length=0x6000;}
    if(*depth==2){*address=0x7000;*length=0x1000;step->isSubmap=0;step->protection=f->mode==1?1:5;}
    return 0;
}
int main(void) {
    Fixture f={.target=0x7100};DHVMMapping m=dh_vm_walk(f.target,query,&f);
    assert(m.found && m.count==3 && dh_vm_executable(&m));
    assert(m.steps[2].start==0x7000 && m.steps[2].inputAddress==f.target);
    f=(Fixture){.target=0x7100,.mode=1};m=dh_vm_walk(f.target,query,&f);assert(m.found && !dh_vm_executable(&m));
    f=(Fixture){.target=0x7100,.mode=2};m=dh_vm_walk(f.target,query,&f);assert(m.kernelError==5 && !m.found && !dh_vm_executable(&m));
    f=(Fixture){.target=0x7100,.mode=3};m=dh_vm_walk(f.target,query,&f);assert(m.invalidRegion && !m.found);
    f=(Fixture){.target=0x7100,.mode=4};m=dh_vm_walk(f.target,query,&f);assert(m.invalidRegion && !m.found);
    f=(Fixture){.target=0x7100,.mode=5};m=dh_vm_walk(f.target,query,&f);assert(m.limitReached && m.count==DH_VM_WALK_MAX && !m.found);
    puts("PASS: target survives nested submaps; data/gap/kernel errors/invalid regions/depth limit fail closed");
    return 0;
}
