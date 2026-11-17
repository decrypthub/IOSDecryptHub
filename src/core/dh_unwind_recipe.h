#ifndef DH_UNWIND_RECIPE_H
#define DH_UNWIND_RECIPE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

// A deliberately bounded A64 validator, independent of unwinder metadata and
// disassembler writeback annotations. Offsets are relative to incoming SP.
#define DH_RECIPE_INSNS 256
#define DH_RECIPE_FRAME 512
#define DH_RECIPE_ABSENT INT16_MIN
typedef struct {
    int16_t sp,fp,saved[12]; // x19..x30; original register values, not spills of modified values
    uint16_t dirty;
    uint8_t fpKnown,seen;
} DHRecipePoint;
typedef struct {
    unsigned count,eligible;
    DHRecipePoint points[DH_RECIPE_INSNS];
} DHFrameRecipe;
enum {
    DH_RECIPE_RESTORE_OK=0,DH_RECIPE_BODY_UNVERIFIED,DH_RECIPE_STACK_BOUNDS,
    DH_RECIPE_FRAME_RELATION,DH_RECIPE_STACK_READ,DH_RECIPE_SAVED_FP,
    DH_RECIPE_RETURN_PC,DH_RECIPE_CALLSITE
};
typedef int (*DHRecipeRead)(void *,uint64_t,void *,size_t);
typedef int (*DHRecipeExecutable)(void *,uint64_t);

static inline unsigned dh_recipe_restore(const DHRecipePoint *point,const uint64_t input[31],uint64_t sp,uint64_t fp,
    uint64_t low,uint64_t high,DHRecipeRead read,DHRecipeExecutable executable,void *context,
    uint64_t output[31],uint64_t *callerSP,uint64_t *callerPC);

static inline int64_t dh_recipe_signed(uint32_t value,unsigned bits) {
    return (int64_t)(value & ((1u<<bits)-1))-(int64_t)((value>>(bits-1))&1)*(1LL<<bits);
}
static inline int dh_recipe_write(DHRecipePoint *s,unsigned reg) {
    if(reg==31)return 1; // ZR in the recognized non-SP instruction classes
    if(reg==18 || reg==29)return 0; // Darwin platform register / noncanonical FP write
    if(reg>=19) {
        unsigned i=reg-19;
        if(s->saved[i]==DH_RECIPE_ABSENT)return 0;
        s->dirty|=(uint16_t)(1u<<i);
    }
    return 1;
}
static inline int dh_recipe_eligible(const DHRecipePoint *s) {
    if(!s->seen || !s->fpKnown || s->sp>=0 || s->fp<s->sp || s->fp>-16)return 0;
    if(s->saved[10]!=s->fp || s->saved[11]!=s->fp+8)return 0;
    for(unsigned i=0;i<12;i++)if((s->dirty&(1u<<i)) || i>=10)
        if(s->saved[i]<s->sp || s->saved[i]>-8)return 0;
    return 1;
}
static inline int dh_recipe_adjust(DHRecipePoint *s,int change) {
    int next=s->sp+change;
    if(next>0 || next< -DH_RECIPE_FRAME || next%16)return 0;
    for(unsigned i=0;i<12;i++)if(s->saved[i]!=DH_RECIPE_ABSENT && s->saved[i]<next) {
        if(s->dirty&(1u<<i))return 0;
        s->saved[i]=DH_RECIPE_ABSENT;
    }
    s->sp=(int16_t)next;return 1;
}
static inline int dh_recipe_store(DHRecipePoint *s,int offset,unsigned width,unsigned reg) {
    if(offset<s->sp || offset+(int)width>0)return 0;
    for(unsigned i=0;i<12;i++)if(s->saved[i]!=DH_RECIPE_ABSENT &&
        offset<s->saved[i]+8 && offset+(int)width>s->saved[i]) {
        if(reg!=i+19 || width!=8 || offset!=s->saved[i] || (s->dirty&(1u<<i)))return 0;
    }
    if(reg>=19 && reg<=30 && width==8 && !(s->dirty&(1u<<(reg-19)))) {
        unsigned i=reg-19;
        if(s->saved[i]!=DH_RECIPE_ABSENT && s->saved[i]!=offset)return 0;
        s->saved[i]=(int16_t)offset;
    }
    return 1;
}
static inline int dh_recipe_load(DHRecipePoint *s,int offset,unsigned width,unsigned reg,int stack) {
    if(reg>=19 && reg<=30 && stack && width==8 && s->saved[reg-19]==offset) {
        s->dirty&=(uint16_t)~(1u<<(reg-19));
        if(reg==29){s->fpKnown=0;s->fp=0;}
        return 1;
    }
    return dh_recipe_write(s,reg);
}
static inline int dh_recipe_clean_exit(const DHRecipePoint *s) {return s->sp==0 && s->dirty==0 && !s->fpKnown;}

// Every reachable control-flow join must have one exact stack/save state.
// Unreachable literal/padding bytes are not interpreted as instructions.
static inline int dh_recipe_validate(const uint32_t *words,unsigned count,DHFrameRecipe *out,char *error,size_t errorSize) {
    if(error && errorSize)error[0]=0;
    if(!out || !words || !count || count>DH_RECIPE_INSNS)return 0;
    memset(out,0,sizeof(*out));out->count=count;
    unsigned work[DH_RECIPE_INSNS],head=0,tail=0;
    DHRecipePoint entry={.seen=1};for(unsigned i=0;i<12;i++)entry.saved[i]=DH_RECIPE_ABSENT;
    out->points[0]=entry;work[tail++]=0;
    const char *reason="unsupported instruction";unsigned at=0;
    while(head<tail) {
        at=work[head++];uint32_t w=words[at];DHRecipePoint s=out->points[at];
        int next[2]={(int)at+1,0};unsigned edges=1;int fallthrough=1;
        unsigned rt=w&31,rn=(w>>5)&31,rm=(w>>16)&31;
        if(w==0xd503201f || w==0xd503245f || w==0xd503249f || w==0xd50324df) {
            // NOP / BTI, never PAC sign/authentication hints.
        } else if((w&0xfe000000)==0xa8000000) {
            unsigned mode=(w>>23)&3,load=(w>>22)&1,rt2=(w>>10)&31;
            int immediate=(int)dh_recipe_signed(w>>15,7)*8;
            int stack=rn==31 || rn==29,offset=0;
            if(!mode || (rn!=31 && mode!=2)){reason="unsupported pair addressing/writeback";goto fail;}
            if(mode==3) {
                if(load || immediate>=0 || !dh_recipe_adjust(&s,immediate)){reason="noncanonical pair allocation";goto fail;}
            }
            if(stack) {
                if(rn==29 && !s.fpKnown){reason="unknown frame-pointer base";goto fail;}
                offset=(rn==31?s.sp:s.fp)+(mode==2?immediate:0);
            }
            if(load) {
                if(rt==rt2 || !dh_recipe_load(&s,offset,8,rt,stack) || !dh_recipe_load(&s,offset+8,8,rt2,stack)){reason="unproven pair restore/write";goto fail;}
            } else if(stack && (!dh_recipe_store(&s,offset,8,rt) || !dh_recipe_store(&s,offset+8,8,rt2))) {
                reason="pair store overwrites/outlives saved state";goto fail;
            }
            if(mode==1 && (!load || immediate<=0 || !dh_recipe_adjust(&s,immediate))){reason="noncanonical pair deallocation";goto fail;}
        } else if((w&0x1f800000)==0x11000000) {
            unsigned sf=w>>31,sub=(w>>30)&1,flags=(w>>29)&1;
            int immediate=(int)((w>>10)&4095)<<(((w>>22)&1)?12:0);
            if(rt==31 && !flags) {
                if(!sf || rn!=31 || !dh_recipe_adjust(&s,sub?-immediate:immediate)){reason="dynamic or oversized SP adjustment";goto fail;}
            } else if(rt==29) {
                if(!sf || sub || flags || rn!=31 || s.fpKnown || immediate%16 || immediate>DH_RECIPE_FRAME || s.sp+immediate>-16 || s.saved[10]!=s.sp+immediate || s.saved[11]!=s.sp+immediate+8) {reason="noncanonical FP establishment";goto fail;}
                s.fp=(int16_t)(s.sp+immediate);s.fpKnown=1;s.dirty|=1u<<10;
            } else if(!(flags && rt==31)) {
                if(rn==31 || rn==29 || !dh_recipe_write(&s,rt)){reason="stack-address escape/unsaved register write";goto fail;}
            }
        } else if((w&0x1f000000)==0x0a000000) {
            unsigned sf=w>>31;
            if(!sf && ((w>>10)&63)>31){reason="invalid logical immediate shift";goto fail;}
            if(sf && (w&0xffffffe0)==(0xaa0003e0|(rt<<16))) {
                // ORR Xd, XZR, Xd (MOV Xd,Xd) preserves even FP.
            } else if(rn==29 || rm==29 || !dh_recipe_write(&s,rt)){reason="FP escape or unsaved logical destination";goto fail;}
        } else if((w&0x1f200000)==0x0b000000) {
            unsigned sf=w>>31;
            if(((w>>22)&3)==3 || (!sf && ((w>>10)&63)>31) || rn==29 || rm==29 || !dh_recipe_write(&s,rt)){reason="unsupported arithmetic register write";goto fail;}
        } else if((w&0x1f000000)==0x10000000) {
            if(!dh_recipe_write(&s,rt)){reason="unsaved address destination";goto fail;}
        } else if((w&0x1f800000)==0x12800000) {
            if(((w>>29)&3)==1 || (!(w>>31) && ((w>>21)&3)>1) || !dh_recipe_write(&s,rt)){reason="unsupported wide immediate destination";goto fail;}
        } else if((w&0x3b000000)==0x39000000 && !(w&0x04000000)) {
            unsigned size=w>>30,op=(w>>22)&3,width=1u<<size;
            int stack=rn==31 || rn==29;
            if(op>1 || (rn==29 && !s.fpKnown)){reason="unsupported scalar access";goto fail;}
            int offset=(rn==31?s.sp:s.fp)+(int)(((w>>10)&4095)*width);
            if(op) {
                if(!dh_recipe_load(&s,offset,width,rt,stack)){reason="unproven scalar restore/write";goto fail;}
            } else if(stack && !dh_recipe_store(&s,offset,width,rt)){reason="scalar store overwrites saved state";goto fail;}
        } else if((w&0x3b000000)==0x18000000 && !(w&0x04000000)) {
            if((w>>30)==3 || !dh_recipe_write(&s,rt)){reason="unsupported literal destination";goto fail;}
        } else if((w&0xfc000000)==0x94000000 || (w&0xfffffc1f)==0xd63f0000) {
            if(s.saved[11]==DH_RECIPE_ABSENT){reason="call without saved original LR";goto fail;}
            if((w&0xfc000000)==0x94000000) {
                int64_t destination=(int64_t)at+dh_recipe_signed(w,26);
                if(destination>=0 && destination<count){reason="internal subroutine entry unsupported";goto fail;}
            }
            s.dirty|=1u<<11;
        } else if((w&0xfc000000)==0x14000000) {
            next[0]=(int)((int64_t)at+dh_recipe_signed(w,26));fallthrough=0;
        } else if((w&0xff000010)==0x54000000 || (w&0x7e000000)==0x34000000 || (w&0x7e000000)==0x36000000) {
            edges=2;unsigned bits=(w&0x7e000000)==0x36000000?14:19;
            next[1]=(int)((int64_t)at+dh_recipe_signed(w>>5,bits));
        } else if(w==0xd65f03c0) {
            if(!dh_recipe_clean_exit(&s)){reason="return before complete original state restore";goto fail;}
            edges=0;
        } else {reason="unknown instruction/PAC/indirect control flow";goto fail;}
        for(unsigned n=0;n<edges;n++) {
            if(next[n]<0 || (unsigned)next[n]>=count) {
                // Only an explicit branch may exit the declared function.
                if((n==0 && fallthrough) || !dh_recipe_clean_exit(&s)){reason="unproven function exit";goto fail;}
                continue;
            }
            DHRecipePoint *old=&out->points[next[n]];
            if(old->seen) {if(memcmp(old,&s,sizeof(s))){reason="inconsistent control-flow stack/save state";goto fail;}}
            else {*old=s;old->seen=1;work[tail++]=(unsigned)next[n];}
        }
    }
    for(unsigned i=0;i<count;i++)out->eligible+=dh_recipe_eligible(&out->points[i]);
    if(!out->eligible){reason="no verified framed body";goto fail;}
    return 1;
fail:
    if(error && errorSize)snprintf(error,errorSize,"instruction %u: %s",at,reason);
    memset(out,0,sizeof(*out));return 0;
}

static inline unsigned dh_recipe_restore(const DHRecipePoint *s,const uint64_t input[31],uint64_t sp,uint64_t fp,
    uint64_t low,uint64_t high,DHRecipeRead read,DHRecipeExecutable executable,void *context,
    uint64_t output[31],uint64_t *callerSP,uint64_t *callerPC) {
    if(!dh_recipe_eligible(s))return DH_RECIPE_BODY_UNVERIFIED;
    unsigned frameSize=(unsigned)-s->sp;
    if(low>=high || sp<low || sp%16 || frameSize>DH_RECIPE_FRAME || sp>UINT64_MAX-frameSize || sp+frameSize>high)return DH_RECIPE_STACK_BOUNDS;
    uint64_t top=sp+frameSize;
    if(fp!=top-(unsigned)-s->fp)return DH_RECIPE_FRAME_RELATION;
    uint8_t bytes[DH_RECIPE_FRAME];
    if(!read(context,sp,bytes,frameSize))return DH_RECIPE_STACK_READ;
    uint64_t values[31];memcpy(values,input,sizeof(values));
    for(unsigned i=0;i<12;i++)if(s->saved[i]!=DH_RECIPE_ABSENT) {
        int offset=(int)frameSize+s->saved[i];
        if(offset<0 || offset+8>(int)frameSize)return DH_RECIPE_BODY_UNVERIFIED;
        memcpy(&values[i+19],bytes+offset,8);
    }
    if(values[29] && (values[29]%16 || values[29]<top || high<16 || values[29]>high-16))return DH_RECIPE_SAVED_FP;
    uint64_t lr=values[30];
    if(lr<4 || lr%4 || !executable(context,lr) || !executable(context,lr-4))return DH_RECIPE_RETURN_PC;
    uint32_t call=0;
    if(!read(context,lr-4,&call,4) || ((call&0xfc000000)!=0x94000000 && (call&0xfffffc1f)!=0xd63f0000))return DH_RECIPE_CALLSITE;
    memcpy(output,values,sizeof(values));*callerSP=top;*callerPC=lr-4;
    return DH_RECIPE_RESTORE_OK;
}
#endif
