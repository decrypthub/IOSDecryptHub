#ifndef DH_VM_MAP_H
#define DH_VM_MAP_H
#include <stdint.h>
#include <string.h>

#define DH_VM_WALK_MAX 16
typedef struct {
    uint64_t inputAddress,start,length;
    unsigned requestedDepth,depth,protection,maxProtection;
    int isSubmap,kernelError;
} DHVMRegion;
typedef struct {
    uint64_t address;
    unsigned count;
    int found,limitReached,invalidRegion,kernelError;
    DHVMRegion steps[DH_VM_WALK_MAX];
} DHVMMapping;
typedef int (*DHVMRegionQuery)(void *,uint64_t *,uint64_t *,unsigned *,DHVMRegion *);

// A recurse call returns the containing region's start through its address
// parameter. Descending must query the original target, not that returned start.
static inline DHVMMapping dh_vm_walk(uint64_t address,DHVMRegionQuery query,void *context) {
    DHVMMapping result={0};result.address=address;
    unsigned depth=0;
    for(unsigned i=0;i<DH_VM_WALK_MAX;i++) {
        uint64_t region=address,length=0;unsigned level=depth;
        DHVMRegion *step=&result.steps[result.count++];
        step->inputAddress=address;step->requestedDepth=depth;
        int error=query(context,&region,&length,&level,step);
        step->start=region;step->length=length;step->depth=level;step->kernelError=error;
        if(error){result.kernelError=error;return result;}
        if(!length || region>address || address-region>=length){result.invalidRegion=1;return result;}
        if(!step->isSubmap){result.found=1;return result;}
        if(level<depth || level==UINT32_MAX){result.invalidRegion=1;return result;}
        depth=level+1;
    }
    result.limitReached=1;return result;
}
static inline int dh_vm_executable(const DHVMMapping *mapping) {
    return mapping->found && mapping->count &&
        (mapping->steps[mapping->count-1].protection & 4)!=0;
}

#ifdef __APPLE__
#include <mach/mach.h>
static inline int dh_vm_query_self(void *unused,uint64_t *address,uint64_t *length,unsigned *depth,DHVMRegion *step) {
    (void)unused;
    vm_address_t region=(vm_address_t)*address;vm_size_t size=0;natural_t nesting=*depth;
    vm_region_submap_info_data_64_t info={0};mach_msg_type_number_t count=VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t error=vm_region_recurse_64(mach_task_self(),&region,&size,&nesting,
        (vm_region_recurse_info_t)&info,&count);
    *address=region;*length=size;*depth=nesting;
    if(error==KERN_SUCCESS){step->isSubmap=info.is_submap;step->protection=info.protection;step->maxProtection=info.max_protection;}
    return error;
}
static inline DHVMMapping dh_vm_mapping(uint64_t address) {return dh_vm_walk(address,dh_vm_query_self,0);}
static inline int dh_vm_address_executable(uint64_t address) {DHVMMapping mapping=dh_vm_mapping(address);return dh_vm_executable(&mapping);}
#endif
#endif
