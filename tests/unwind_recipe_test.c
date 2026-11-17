#include "dh_unwind_recipe.h"
#include <assert.h>
#include <stdio.h>

// Owned example, not copied App code: conditional leaf path, saved x19/x20,
// original frame record, a real external call and fully restored tail branch.
static const uint32_t framed[]={
    0xb40001c0,0xa9be4ff4,0xa9017bfd,0x910043fd,0xaa0003f3,
    0xaa0103f4,0x94000100,0xaa1d03fd,0xb4000060,0xf9400260,
    0xf9000280,0xa9417bfd,0xa8c24ff4,0x14000100,0xd65f03c0
};
typedef struct {uint8_t stack[256];uint32_t call;int readable;} Memory;
static int read_memory(void *opaque,uint64_t address,void *out,size_t length) {
    Memory *m=opaque;
    if(address==0x2000 && length==4){memcpy(out,&m->call,4);return 1;}
    if(!m->readable || address<0x1000 || address-0x1000>sizeof(m->stack) || length>sizeof(m->stack)-(address-0x1000))return 0;
    memcpy(out,m->stack+address-0x1000,length);return 1;
}
static int executable(void *opaque,uint64_t address) {(void)opaque;return address>=0x2000 && address<0x3000;}
static void word(Memory *m,unsigned offset,uint64_t value) {memcpy(m->stack+offset,&value,8);}
static void bad(unsigned index,uint32_t replacement) {
    uint32_t code[sizeof(framed)/4];memcpy(code,framed,sizeof(code));code[index]=replacement;
    DHFrameRecipe recipe;char error[160];
    if(dh_recipe_validate(code,sizeof(code)/4,&recipe,error,sizeof(error))) {fprintf(stderr,"unexpected acceptance at %u: %08x\n",index,replacement);assert(0);}
    assert(error[0]);assert(!recipe.count && !recipe.eligible);
}
int main(void) {
    DHFrameRecipe recipe;char error[160];
    assert(dh_recipe_validate(framed,sizeof(framed)/4,&recipe,error,sizeof(error)));
    assert(recipe.count==15 && recipe.eligible==8);
    assert(!dh_recipe_eligible(&recipe.points[0]) && !dh_recipe_eligible(&recipe.points[3]) && dh_recipe_eligible(&recipe.points[4]) && !dh_recipe_eligible(&recipe.points[12]));
    const DHRecipePoint *p=&recipe.points[7];assert(p->sp==-32 && p->fp==-16);
    assert(p->saved[0]==-24 && p->saved[1]==-32 && p->saved[10]==-16 && p->saved[11]==-8);
    uint32_t common[sizeof(framed)/4];memcpy(common,framed,sizeof(common));common[13]=0x14000001;
    assert(dh_recipe_validate(common,15,&recipe,error,sizeof(error))); // clean body/leaf CFG merge
    assert(dh_recipe_validate(common,14,&recipe,error,sizeof(error))); // explicit tail to adjacent function
    bad(0,0xb4000080); // bypass frame establishment
    bad(4,0x9100001f); // dynamic SP
    bad(4,0xd10043ff); // an unbalanced additional frame allocation
    bad(4,0xaa0003f5); // unsaved x21
    bad(4,0xaa0003f2); // reserved Darwin x18
    bad(4,0x910003e8); // escape SP into an alias
    bad(4,0x1e682908); // unsupported SIMD
    bad(4,0xd503237f); // PACIBSP is not a no-op hint
    bad(4,0xf9000be0); // overwrite original frame record
    bad(4,0xf940001d); // arbitrary FP overwrite
    bad(6,0x97fffffb); // internal call entry
    bad(8,0xb40000c0); // framed path jumps to leaf return
    bad(11,0xa9407bfd); // restore from wrong slots
    bad(13,0xd61f0000); // indirect exit is not guessed
    bad(4,0); // undecodable instruction
    Memory memory={.call=0x94000004,.readable=1};
    word(&memory,0,0x20202020);word(&memory,8,0x19191919);word(&memory,16,0x1080);word(&memory,24,0x2004);
    assert(dh_recipe_validate(framed,15,&recipe,error,sizeof(error)));p=&recipe.points[7];
    uint64_t input[31],output[31],sp=0,pc=0;for(unsigned i=0;i<31;i++)input[i]=0xdead0000+i;
#define RESTORE(SP,FP,LO,HI) dh_recipe_restore(p,input,(SP),(FP),(LO),(HI),read_memory,executable,&memory,output,&sp,&pc)
    assert(RESTORE(0x1000,0x1010,0x1000,0x1100)==0);
    assert(sp==0x1020 && pc==0x2000 && output[19]==0x19191919 && output[20]==0x20202020 && output[29]==0x1080 && output[30]==0x2004);
    for(unsigned i=0;i<31;i++)if(i!=19 && i!=20 && i!=29 && i!=30)assert(output[i]==input[i]);
    assert(RESTORE(0x1001,0x1011,0x1000,0x1100)==DH_RECIPE_STACK_BOUNDS);
    assert(RESTORE(0x1000,0x1018,0x1000,0x1100)==DH_RECIPE_FRAME_RELATION);
    assert(RESTORE(0x1000,0x1010,0x1008,0x1100)==DH_RECIPE_STACK_BOUNDS);
    assert(RESTORE(0x1000,0x1010,0x1000,0x1010)==DH_RECIPE_STACK_BOUNDS);
    memory.readable=0;assert(RESTORE(0x1000,0x1010,0x1000,0x1100)==DH_RECIPE_STACK_READ);memory.readable=1;
    word(&memory,16,0x1000);assert(RESTORE(0x1000,0x1010,0x1000,0x1100)==DH_RECIPE_SAVED_FP);word(&memory,16,0x1080);
    word(&memory,24,0xab00000000002004);assert(RESTORE(0x1000,0x1010,0x1000,0x1100)==DH_RECIPE_RETURN_PC);word(&memory,24,0x2004);
    memory.call=0xd503201f;assert(RESTORE(0x1000,0x1010,0x1000,0x1100)==DH_RECIPE_CALLSITE);
    memory.call=0xd63f0100;assert(RESTORE(0x1000,0x1010,0x1000,0x1100)==0); // BLR x8
    puts("PASS: canonical CFG/save-state and bounded caller reconstruction, including original x19/x20; all corruption/unknown cases refused");
    return 0;
}
