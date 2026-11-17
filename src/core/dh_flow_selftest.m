#import "dh_flow.h"
#import "dh_thunk.h"
#import "dh_event.h"
#import "dh_call_context.h"
#import "log_store.h"
#include <setjmp.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
extern void DHFlowThrowCXX(void);
extern int DHFlowCatchCXX(void (*body)(void *),void *context);
extern int dh_thunk_post_frame(uint64_t pc,uint64_t sp,uint64_t callerSP);
static __thread jmp_buf *jumpTarget;
static void require(BOOL good,NSString *message);
@interface IDHFlowProbe:NSObject
@property(strong) NSException *marker;
@property(strong) NSMutableArray *observations;
@property(strong) dispatch_queue_t queue;
@property(strong) dispatch_group_t group;
@property int mode;
@property(copy) dispatch_block_t special;
- (uint64_t)normal:(uint64_t)n;
- (uint64_t)throwOut;
- (uint64_t)jumpOut;
- (uint64_t)cppOut;
- (uint64_t)catchInside;
- (uint64_t)schedule;
- (uint64_t)exitOut;
- (uint64_t)unverified;
- (uint64_t)partial;
@end
static void cpp_body(void *p) {[( __bridge IDHFlowProbe *)p cppOut];}
static void *exit_body(void *p) {[( __bridge IDHFlowProbe *)p exitOut];return NULL;}
static void function_body(void *p) {IDHFlowProbe *probe=CFBridgingRelease(p);[probe normal:17];dispatch_group_leave(probe.group);}
@implementation IDHFlowProbe
- (uint64_t)normal:(uint64_t)n {
    @synchronized(self) {[self.observations addObject:@{@"asyncTaskId":DHFlowFields(dh_call_async())[@"asyncTaskId"],@"parentCallId":DHCallID(dh_call_parent())}];}
    return n+1;
}
- (uint64_t)throwOut {@throw self.marker;}
- (uint64_t)jumpOut {longjmp(*jumpTarget,73);}
- (uint64_t)cppOut {DHFlowThrowCXX();return 0;}
- (uint64_t)exitOut {pthread_exit(NULL);}
- (uint64_t)unverified {
    DHRawStack unknown={0};DHFlowCheck(&unknown);
    if(dh_call_parent() || dh_call_async())[NSException raise:@"IDHFlowFixture" format:@"unverified boundary retained an association"];
    unknown.complete=1;unknown.count=1;unknown.pc[0]=1;unknown.sp[0]=1;DHFlowCheck(&unknown);
    if(dh_call_parent() || dh_call_async())[NSException raise:@"IDHFlowFixture" format:@"premature stop retained an association"];
    return [self normal:1];
}
- (uint64_t)partial {
    DHRawStack stack;dh_unwind_current(&stack);BOOL bridge=NO;
    for(unsigned i=0;i<stack.count;i++)if(dh_thunk_post_frame(stack.pc[i],stack.sp[i],stack.sp[i]+0x560) || dh_thunk_post_frame(stack.pc[i],stack.sp[i],stack.sp[i]+0x460)){stack.count=i+1;bridge=YES;break;}
    require(bridge,@"partial fixture did not capture the real active post bridge");
    stack.complete=0;stack.truncated=1;stack.stopReason=DH_UNWIND_FRAME_LIMIT;
    DHFlowCheck(&stack);require(dh_call_parent()!=0,@"verified active bridge lost parent because higher frames were truncated");
    return 42;
}
- (uint64_t)catchInside {@try {@throw self.marker;}@catch(NSException *e) {return [self normal:8];}}
- (uint64_t)schedule {
    dispatch_group_t group=self.group;dispatch_queue_t queue=self.queue;
    if(self.mode==1) {dispatch_group_enter(group);dispatch_after(dispatch_time(DISPATCH_TIME_NOW,50000000),queue,^{[self normal:9];dispatch_group_leave(group);});return 1;}
    if(self.mode==2) {self.special=dispatch_block_create(DISPATCH_BLOCK_BARRIER,^{[self normal:99];});dispatch_block_cancel(self.special);dispatch_async(queue,self.special);return 0;}
    if(self.mode==3) {
        dispatch_group_enter(group);dispatch_async(queue,^{
            // A live parent must propagate even when new roots no longer match.
            DHFlowConfigure(YES,NO,8,10000,nil,@[@"nonmatching-root"]);
            dispatch_group_enter(group);dispatch_async(queue,^{[self normal:23];dispatch_group_leave(group);});dispatch_group_leave(group);
        });return 0;
    }
    if(self.mode==4) {
        dispatch_group_enter(group);dispatch_block_t block=dispatch_block_create(DISPATCH_BLOCK_BARRIER,^{[self normal:31];dispatch_group_leave(group);});
        dispatch_async(queue,block);require(dispatch_block_wait(block,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"created block wait changed");
        dispatch_group_enter(group);dispatch_block_t qos=dispatch_block_create_with_qos_class(0,QOS_CLASS_UTILITY,0,^{[self normal:32];dispatch_group_leave(group);});
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,1000000),queue,qos);require(dispatch_block_wait(qos,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"QoS block wait changed");return 0;
    }
    if(self.mode==5) {
        dispatch_suspend(queue);dispatch_group_enter(group);dispatch_group_enter(group);
        dispatch_block_t block=dispatch_block_create(0,^{[self normal:33];dispatch_group_leave(group);});
        dispatch_async(queue,block);dispatch_async(queue,block);dispatch_resume(queue);return 0;
    }
    if(self.mode==6) {
        dispatch_suspend(queue);dispatch_group_enter(group);dispatch_group_enter(group);
        dispatch_block_t block=dispatch_block_create(0,^{[self normal:34];dispatch_group_leave(group);});
        dispatch_async(queue,block);block();dispatch_resume(queue);return 0;
    }
    dispatch_group_enter(group);dispatch_async(queue,^{
        [self normal:1];dispatch_group_enter(group);dispatch_async(queue,^{[self normal:2];dispatch_group_leave(group);});dispatch_group_leave(group);
    });
    dispatch_group_enter(group);dispatch_after(dispatch_time(DISPATCH_TIME_NOW,1000000),queue,^{[self normal:3];dispatch_group_leave(group);});
    dispatch_group_async(group,queue,^{[self normal:4];});
    dispatch_group_enter(group);dispatch_async_f(queue,(__bridge_retained void *)self,function_body);
    dispatch_group_enter(group);dispatch_after_f(dispatch_time(DISPATCH_TIME_NOW,1000000),queue,(__bridge_retained void *)self,function_body);
    dispatch_group_enter(group);dispatch_group_async_f(group,queue,(__bridge_retained void *)self,function_body);
    return 7;
}
@end
static void require(BOOL good,NSString *message) {if(!good)[NSException raise:@"IDHFlowFixture" format:@"%@",message];}
static void drain(IDHFlowProbe *probe) {
    require(dispatch_group_wait(probe.group,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"fixture callbacks timed out");
    for(unsigned i=0;i<100 && [DHFlowState()[@"pendingOrRunning"] unsignedIntValue];i++)usleep(10000);
    require([DHFlowState()[@"pendingOrRunning"] unsignedIntValue]==0,@"pending task accounting leaked");
}
NSDictionary *DHFlowSelfTest(void) {
    NSMutableArray *passed=[NSMutableArray array],*slots=[NSMutableArray array];NSMutableDictionary *result=[@{@"pass":@NO,@"restartRequired":@YES} mutableCopy];
    IDHFlowProbe *probe=[IDHFlowProbe new];probe.marker=[NSException exceptionWithName:@"IDH-original-marker" reason:@"fixture" userInfo:nil];probe.observations=[NSMutableArray array];
    probe.queue=dispatch_queue_create("com.iosdecrypthub.flow.fixture",DISPATCH_QUEUE_SERIAL);probe.group=dispatch_group_create();
    @try {
        require(![DHLogStore shared].paused && ![[DHLogStore shared] isPausedForCategory:DHCategoryOther],@"resume all/other before selftest");
        dh_hook_options options;dh_thunk_options_default(&options);options.fixed_abi=1;options.capture_return=1;char error[512]={0};
        for(NSString *name in @[@"normal:",@"throwOut",@"jumpOut",@"cppOut",@"catchInside",@"schedule",@"exitOut",@"unverified",@"partial"]) {
            int slot=dh_thunk_install_configured(DH_HOOK_METHOD,"IDHFlowProbe",name.UTF8String,0,0,NULL,&options,error,sizeof(error));require(slot>=0,@(error));[slots addObject:@(slot)];
        }
        uint64_t initial=[DHFlowState()[@"abandonedCalls"] unsignedLongLongValue];
        @try {[probe throwOut];require(NO,@"throw did not propagate");}@catch(NSException *e) {require(e==probe.marker,@"original exception object changed");}
        require([probe normal:6]==7 && dh_call_parent()==0,@"exception left a stale parent");
        require([DHFlowState()[@"abandonedCalls"] unsignedLongLongValue]==initial+1,@"exception bridge not retired");
        [passed addObject:@"ObjC-exception-propagates-and-abandoned-post-retires"];
        jmp_buf env;jumpTarget=&env;int value=setjmp(env);if(!value)[probe jumpOut];require(value==73,@"longjmp result changed");
        require([probe normal:3]==4 && dh_call_parent()==0,@"longjmp left a stale parent");
        require([DHFlowState()[@"abandonedCalls"] unsignedLongLongValue]==initial+2,@"longjmp bridge not retired");[passed addObject:@"longjmp-preserves-value-and-cleans-next-boundary"];
        require(DHFlowCatchCXX(cpp_body,(__bridge void *)probe)==73,@"C++ exception did not propagate unchanged");[probe normal:2];
        require([DHFlowState()[@"abandonedCalls"] unsignedLongLongValue]==initial+3,@"C++ bridge not retired");[passed addObject:@"CXX-exception-propagates-and-abandoned-post-retires"];
        require([probe catchInside]==9,@"caught-inside result changed");require([DHFlowState()[@"abandonedCalls"] unsignedLongLongValue]==initial+3,@"caught-inside falsely retired active bridge");[passed addObject:@"caught-inside-keeps-active-parent"];
        [DHLogStore shared].paused=YES;value=setjmp(env);if(!value)[probe jumpOut];[probe normal:0];[DHLogStore shared].paused=NO;
        require([DHFlowState()[@"abandonedCalls"] unsignedLongLongValue]==initial+4,@"paused bridge accounting leaked");[passed addObject:@"paused-capture-still-protects-inflight-state"];
        require([probe unverified]==2,@"incomplete unwind did not suppress uncertain links");[passed addObject:@"incomplete-unwind-suppresses-links-without-false-abort"];
        uint64_t partialBefore=[DHFlowState()[@"verifiedPartialBoundaries"] unsignedLongLongValue];
        require([probe partial]==42 && [DHFlowState()[@"verifiedPartialBoundaries"] unsignedLongLongValue]==partialBefore+1,@"positive owned-frame evidence did not survive a partial walk");
        require([DHFlowDiagnostics(0,4)[@"records"] count]>0,@"uncertain boundaries missing diagnostic records");
        [passed addObject:@"partial-stack-with-all-real-owned-anchors-keeps-proven-parent"];
        pthread_t worker;require(pthread_create(&worker,NULL,exit_body,(__bridge void *)probe)==0,@"thread fixture creation failed");pthread_join(worker,NULL);
        require([DHFlowState()[@"abandonedCalls"] unsignedLongLongValue]==initial+5,@"thread exit did not retire owned bridge");[passed addObject:@"thread-exit-retires-inflight-state"];
        NSDictionary *configured=DHFlowConfigure(YES,NO,64,10000,nil,nil);require([configured[@"ok"] boolValue],configured[@"error"]);
        unsigned first=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];[probe schedule];drain(probe);
        NSDictionary *read=DHFlowRead(first,64,0);NSArray *tasks=read[@"tasks"];require(tasks.count==7,@"six APIs plus nested async not captured");
        BOOL nested=NO,cross=NO;for(NSDictionary *t in tasks) {require([t[@"state"] isEqual:@"completed"],@"task not complete");nested|=[t[@"asyncParentTaskId"] length]>0;cross|=![t[@"submissionThreadId"] isEqual:t[@"executionThreadId"]];}
        require(nested && cross && probe.observations.count==7,@"missing nested/cross-thread/exactly-once observations");
        for(NSDictionary *o in probe.observations)require([o[@"asyncTaskId"] length]>0,@"worker lost captured context");
        for(NSDictionary *t in tasks)require([t[@"callbackIdentity"][@"imageUUID"] length]>0 && [t[@"callbackPC"] length]>0,@"callback identity unavailable");
        [passed addObject:@"six-GCD-imports-nested-edges-and-cross-thread-context"];result[@"tasks"]=tasks;
        unsigned filteredBefore=[DHFlowState()[@"retained"] unsignedIntValue];NSUInteger observedBefore=probe.observations.count;
        DHFlowConfigure(YES,NO,8,10000,nil,@[@"nonmatching-root"]);[probe schedule];drain(probe);
        require([DHFlowState()[@"retained"] unsignedIntValue]==filteredBefore && probe.observations.count==observedBefore+7,@"root filter changed original callbacks or accepted unmatched roots");
        require([DHFlowState()[@"rootQueueMisses"] unsignedLongLongValue]>0,@"root filter missing diagnostic count");[passed addObject:@"root-queue-filter-forwards-unmatched-work"];
        DHFlowConfigure(YES,NO,8,10000,nil,@[@"FLOW.FIXTURE"]);probe.mode=3;[probe schedule];drain(probe);probe.mode=0;
        require([DHFlowState()[@"retained"] unsignedIntValue]==filteredBefore+2,@"selected descendant was filtered after changing queues policy");
        NSDictionary *child=[DHFlowRead(filteredBefore+1,1,0)[@"tasks"] firstObject];require([child[@"asyncParentTaskId"] length]>0,@"selected descendant lost parent identity");
        [passed addObject:@"root-queue-filter-is-case-insensitive-and-keeps-descendants"];
        unsigned specialBefore=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];DHFlowConfigure(YES,NO,16,10000,nil,nil);probe.mode=4;[probe schedule];drain(probe);
        NSArray *specialTasks=DHFlowRead(specialBefore,16,0)[@"tasks"];require(specialTasks.count==2 && probe.observations.count==2,@"public block constructors lost or duplicated callbacks");
        for(NSDictionary *t in specialTasks)require([t[@"state"] isEqual:@"completed"] && [t[@"dispatchBlockMetadataPreserved"] boolValue] && [t[@"blockCreationCallerIdentity"][@"imageUUID"] length]>0,@"public block creation/submission identity missing");
        for(NSDictionary *o in probe.observations)require([o[@"asyncTaskId"] length]>0,@"public created-block inner body lost task");
        [passed addObject:@"public-block-constructors-preserve-outer-wait-QoS-and-inner-context"];
        specialBefore=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];DHFlowConfigure(YES,NO,16,10000,nil,nil);probe.mode=5;[probe schedule];drain(probe);probe.mode=0;
        specialTasks=DHFlowRead(specialBefore,16,0)[@"tasks"];require(specialTasks.count==1 && probe.observations.count==2,@"reused block changed original execution count");
        NSDictionary *ambiguous=specialTasks.firstObject;require([ambiguous[@"state"] isEqual:@"unresolved"] && [ambiguous[@"startedNs"] isEqual:@"0"] && [ambiguous[@"terminalReason"] isEqual:@"block-reused-before-observed-start"],@"ambiguous repeated submission invented an execution edge");
        for(NSDictionary *o in probe.observations)require(![o[@"asyncTaskId"] length],@"ambiguous reused block retained an association");
        [passed addObject:@"reused-before-start-forwards-twice-without-guessed-execution-edge"];
        specialBefore=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];DHFlowConfigure(YES,NO,16,10000,nil,nil);probe.mode=6;[probe schedule];drain(probe);probe.mode=0;
        specialTasks=DHFlowRead(specialBefore,16,0)[@"tasks"];require(specialTasks.count==1 && probe.observations.count==2,@"direct-plus-queued block changed original execution count");
        ambiguous=specialTasks.firstObject;require([ambiguous[@"state"] isEqual:@"unresolved"] && [ambiguous[@"startedNs"] isEqual:@"0"] && [ambiguous[@"terminalReason"] isEqual:@"block-executed-outside-calibrated-async-invoker"],@"direct block call falsely claimed queued submission");
        for(NSDictionary *o in probe.observations)require(![o[@"asyncTaskId"] length],@"direct block invocation invented an async edge");
        [passed addObject:@"direct-call-after-enqueue-is-not-an-async-execution"];
        unsigned before=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,2,10000,nil,nil);[probe.observations removeAllObjects];[probe schedule];drain(probe);
        require([DHFlowState()[@"retained"] unsignedIntValue]==before+2 && probe.observations.count==7,@"budget changed original callback execution");[passed addObject:@"task-budget-forwards-all-original-callbacks-once"];
        require([DHFlowState()[@"windowStopReason"] isEqual:@"task-budget"],@"task budget stop reason unavailable");
        before=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,2,1,nil,nil);usleep(3000);[probe schedule];drain(probe);
        require([DHFlowState()[@"retained"] unsignedIntValue]==before,@"expired window captured a new task");[passed addObject:@"expired-window-forwards-without-new-capture"];
        require([DHFlowState()[@"windowStopReason"] isEqual:@"expired"],@"expired stop reason unavailable");
        DHFlowConfigure(YES,NO,2,10000,nil,nil);probe.mode=1;[probe schedule];DHFlowConfigure(NO,NO,2,10000,nil,nil);drain(probe);
        require([probe normal:4]==5 && dh_call_async()==0 && dh_call_parent()==0,@"unrelated worker/caller context leaked");[passed addObject:@"disable-keeps-pending-task-and-does-not-leak-context"];
        before=[DHFlowState()[@"retained"] unsignedIntValue];NSUInteger observed=probe.observations.count;DHFlowConfigure(YES,NO,8,10000,nil,nil);probe.mode=2;[probe schedule];
        require(dispatch_block_wait(probe.special,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"special block wait/cancel semantics changed");
        require(probe.observations.count==observed && [DHFlowState()[@"retained"] unsignedIntValue]==before,@"cancelled dispatch block was wrapped or executed");[passed addObject:@"special-dispatch-block-cancel-wait-is-forwarded-unchanged"];
        for(NSNumber *slot in slots)require([dh_thunk_metadata(slot.intValue)[@"inFlight"] longLongValue]==0,@"owned inflight counter leaked");
        require([DHFlowState()[@"threadGuardCount"] intValue]==0,@"thread guard stack leaked");result[@"pass"]=@YES;
    }@catch(NSException *e) {result[@"error"]=e.reason?:@"flow fixture failed";}
    @finally {jumpTarget=NULL;[DHLogStore shared].paused=NO;DHFlowConfigure(NO,NO,1,1,nil,nil);for(NSNumber *slot in slots)dh_thunk_disable(slot.intValue);}
    result[@"passed"]=passed;result[@"slots"]=slots;result[@"state"]=DHFlowState();return result;
}
