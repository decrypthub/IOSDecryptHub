#import "dh_flow.h"
#import "dh_thunk.h"
#import "dh_event.h"
#import "dh_call_context.h"
#import "log_store.h"
#include <setjmp.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#import "dh_flow_timers.h"
extern void DHFlowThrowCXX(void);
extern int DHFlowCatchCXX(void (*body)(void *),void *context);
extern int dh_thunk_post_frame(uint64_t pc,uint64_t sp,uint64_t callerSP);
static __thread jmp_buf *jumpTarget;
static void require(BOOL good,NSString *message);
@interface DHFlowSourceFixtureRun:NSObject
@property(strong) NSMutableArray *rows;
@property(strong) dispatch_group_t done;
@property uintptr_t source;
@property unsigned events;
@property BOOL spawnChild;
@property(strong) dispatch_queue_t childQueue;
@end
@implementation DHFlowSourceFixtureRun
@end
@interface DHFlowSourceFixtureContext:NSObject
@property(strong) DHFlowSourceFixtureRun *run;
@property(strong) DHFlowSourceFixtureContext *previous;
@property unsigned tag;
@end
@implementation DHFlowSourceFixtureContext
@end
static const char sourceTargetKey;
static void source_record(DHFlowSourceFixtureRun *run,NSString *kind,unsigned tag) {
    @synchronized(run) {[run.rows addObject:@{@"kind":kind,@"tag":@(tag),@"task":DHFlowFields(dh_call_async())[@"asyncTaskId"],@"target":@((uintptr_t)dispatch_get_specific(&sourceTargetKey))}];}
}
static void source_event(DHFlowSourceFixtureRun *run,unsigned tag) {
    source_record(run,@"event",tag);dispatch_source_t source=(__bridge dispatch_source_t)(void *)run.source;
    (void)dispatch_source_get_data(source);
    if(++run.events==1) {
        if(run.spawnChild){dispatch_group_enter(run.done);dispatch_async(run.childQueue,^{source_record(run,@"child",tag);dispatch_group_leave(run.done);});}
        dispatch_source_merge_data(source,2);
    } else dispatch_source_cancel(source);
}
static void source_event_f(void *opaque) {DHFlowSourceFixtureContext *context=(__bridge id)opaque;source_event(context.run,context.tag);}
static void source_cancel_f(void *opaque) {DHFlowSourceFixtureContext *context=(__bridge id)opaque;source_record(context.run,@"cancel",context.tag);dispatch_group_leave(context.run.done);}
static void source_registration_f(void *opaque) {DHFlowSourceFixtureContext *context=(__bridge id)opaque;source_record(context.run,@"registration",context.tag);}
static void source_old_f(void *opaque) {DHFlowSourceFixtureContext *context=(__bridge id)opaque;source_record(context.run,@"replaced-handler-ran",context.tag);}
static void source_finalize_f(void *opaque) {id released=CFBridgingRelease(opaque);(void)released;}
typedef struct {__unsafe_unretained NSMutableArray *rows;unsigned fired,retains,releases;} DHTimerFixtureContext;
static const void *timer_context_retain(const void *opaque) {((DHTimerFixtureContext *)opaque)->retains++;return opaque;}
static void timer_context_release(const void *opaque) {((DHTimerFixtureContext *)opaque)->releases++;}
static void timer_record(NSMutableArray *rows,NSString *kind) {
    CFStringRef mode=CFRunLoopCopyCurrentMode(CFRunLoopGetCurrent());
    [rows addObject:@{@"kind":kind,@"task":DHFlowFields(dh_call_async())[@"asyncTaskId"],@"mode":(__bridge NSString *)mode?:@"<manual>"}];if(mode)CFRelease(mode);
}
static void timer_context_callback(CFRunLoopTimerRef timer,void *opaque) {
    DHTimerFixtureContext *context=opaque;context->fired++;timer_record(context->rows,@"cf-timer");
    if(context->fired==2)CFRunLoopTimerInvalidate(timer);
}
static void timer_source_noop(void *opaque) {(void)opaque;}
@interface IDHFlowProbe:NSObject
@property(strong) NSException *marker;
@property(strong) NSMutableArray *observations;
@property(strong) dispatch_queue_t queue;
@property(strong) dispatch_group_t group;
@property(strong) dispatch_group_t notificationDependency;
@property int mode;
@property(copy) dispatch_block_t special;
@property(strong) NSMutableArray *timerRows;
@property(weak) NSTimer *expectedTimer;
@property(strong) id timerMarker;
@property unsigned timerContextRetains;
@property unsigned timerContextReleases;
- (uint64_t)normal:(uint64_t)n;
- (uint64_t)throwOut;
- (uint64_t)jumpOut;
- (uint64_t)cppOut;
- (uint64_t)catchInside;
- (uint64_t)schedule;
- (uint64_t)exitOut;
- (uint64_t)unverified;
- (uint64_t)partial;
- (NSArray *)sourceMode:(uint64_t)mode;
- (NSArray *)timerMode:(uint64_t)mode;
- (void)timerTick:(NSTimer *)timer;
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
- (NSArray *)sourceMode:(uint64_t)mode {
    DHFlowSourceFixtureRun *run=[DHFlowSourceFixtureRun new];run.rows=[NSMutableArray array];run.done=dispatch_group_create();dispatch_group_enter(run.done);
    run.spawnChild=(mode==21);run.childQueue=self.queue;
    if(mode==16)DHFlowConfigure(NO,NO,1,1,nil,nil);
    dispatch_source_t source=dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD,0,0,self.queue);
    require(source!=nil,@"source fixture creation failed");run.source=(uintptr_t)(__bridge void *)source;
    if(mode==16)DHFlowConfigure(YES,NO,32,10000,nil,nil);
    if(mode==11 || mode==12 || mode==13 || mode==19) {
        DHFlowSourceFixtureContext *first=[DHFlowSourceFixtureContext new];first.run=run;first.tag=1;
        DHFlowSourceFixtureContext *second=[DHFlowSourceFixtureContext new];second.run=run;second.tag=2;second.previous=first;
        dispatch_set_context(source,(__bridge void *)first);
        if(mode==13 || mode==19)dispatch_source_set_event_handler_f(source,source_old_f);
        if(mode==19)dispatch_source_set_event_handler_f(source,NULL);
        dispatch_source_set_event_handler_f(source,source_event_f);
        dispatch_source_set_cancel_handler_f(source,source_cancel_f);
        dispatch_source_set_registration_handler_f(source,source_registration_f);
        // Compare the same sequence with capture off/on. The forwarding slot
        // receives libdispatch's actual context instead of interpreting it.
        dispatch_set_context(source,CFBridgingRetain(second));dispatch_set_finalizer_f(source,source_finalize_f);
    } else {
        dispatch_block_t event=^{source_event(run,3);};
        if(mode==14)event=dispatch_block_create_with_qos_class(DISPATCH_BLOCK_ENFORCE_QOS_CLASS,QOS_CLASS_UTILITY,0,event);
        dispatch_source_set_event_handler(source,event);
        dispatch_source_set_cancel_handler(source,^{source_record(run,@"cancel",3);dispatch_group_leave(run.done);});
        dispatch_source_set_registration_handler(source,^{source_record(run,@"registration",3);});
    }
    if(mode==15) {
        dispatch_queue_t target=dispatch_queue_create("com.iosdecrypthub.flow.fixture.target",DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(target,&sourceTargetKey,(void *)0x345,NULL);dispatch_set_target_queue(source,target);
    }
    if(mode==18)DHFlowConfigure(NO,NO,1,1,nil,nil);
    dispatch_resume(source);dispatch_source_merge_data(source,1);
    long timedOut=dispatch_group_wait(run.done,dispatch_time(DISPATCH_TIME_NOW,5000000000));
    if(timedOut)dispatch_source_cancel(source);
    require(!timedOut,@"source callbacks timed out; cancellation requested, callback storage remains lifetime-owned");
    for(unsigned i=0;i<100 && [DHFlowState()[@"pendingOrRunning"] unsignedIntValue];i++)usleep(10000);
    return [run.rows copy];
}
- (void)timerTick:(NSTimer *)timer {
    timer_record(self.timerRows,timer==self.expectedTimer && timer.userInfo==self.timerMarker?@"native-timer-original-target":@"native-timer-argument-mismatch");
    if(self.timerRows.count==2)[timer invalidate];
}
- (NSArray *)timerMode:(uint64_t)mode {
    NSMutableArray *rows=[NSMutableArray array];CFRunLoopRef loop=CFRunLoopGetCurrent();CFStringRef custom=CFSTR("IDHFlowTimerMode");
    if(mode==11) {
        dispatch_semaphore_t done=dispatch_semaphore_create(0);
        dispatch_queue_t queue=dispatch_queue_create("com.iosdecrypthub.internal-origin.fixture",DISPATCH_QUEUE_SERIAL);
        DHFlowSetOwnedFixtureScope(NO);
        @try {dispatch_async(queue,^{timer_record(rows,@"agent-internal-forwarded");dispatch_semaphore_signal(done);});}
        @finally {DHFlowSetOwnedFixtureScope(YES);}
        require(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"internal origin callback timed out");return rows;
    }
    if(mode==1 || mode==2) {
        DHTimerFixtureContext context={.rows=rows};CFRunLoopTimerContext input={.version=0,.info=&context,.retain=timer_context_retain,.release=timer_context_release};
        CFRunLoopTimerRef timer=CFRunLoopTimerCreate(NULL,CFAbsoluteTimeGetCurrent()+0.001,0.002,0,0,timer_context_callback,&input);
        require(timer!=NULL,@"CF timer fixture creation failed");CFRunLoopTimerContext actual={0};CFRunLoopTimerGetContext(timer,&actual);
        require(actual.info==&context && actual.retain==input.retain && actual.release==input.release && context.retains==1,@"CF timer adapter changed public context or retain semantics");
        CFRunLoopAddTimer(loop,timer,custom);
        if(mode==2){CFRunLoopRemoveTimer(loop,timer,custom);CFRunLoopTimerInvalidate(timer);}
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.01,false);require(!rows.count,@"timer fired in the wrong runloop mode");
        CFRunLoopRunInMode(custom,0.1,false);
        require((mode==1 && rows.count==2) || (mode==2 && !rows.count),@"CF timer repeat/removal behavior changed");
        require(!CFRunLoopTimerIsValid(timer),@"timer invalidation did not reach the original object");
        CFRelease(timer);self.timerContextRetains=context.retains;self.timerContextReleases=context.releases;
        require(context.retains==context.releases,@"CF timer context ownership did not balance before fixture storage left scope");return rows;
    }
    if(mode==3) {
        __block CFRunLoopTimerRef expected=NULL;
        CFRunLoopTimerRef timer=CFRunLoopTimerCreateWithHandler(NULL,CFAbsoluteTimeGetCurrent()+0.001,0,0,0,^(CFRunLoopTimerRef actual){timer_record(rows,actual==expected?@"cf-handler-original-timer":@"cf-handler-mismatch");});
        expected=timer;require(timer!=NULL,@"CF handler fixture creation failed");CFRunLoopAddTimer(loop,timer,custom);CFRunLoopRunInMode(custom,0.1,false);
        require(rows.count==1 && !CFRunLoopTimerIsValid(timer),@"one-shot CF handler behavior changed");CFRelease(timer);return rows;
    }
    if(mode==4) {
        CFRunLoopSourceContext context={.version=0,.perform=timer_source_noop};CFRunLoopSourceRef keepAlive=CFRunLoopSourceCreate(NULL,0,&context);CFRunLoopAddSource(loop,keepAlive,custom);
        CFRunLoopPerformBlock(loop,custom,^{timer_record(rows,@"runloop-block");CFRunLoopStop(loop);});CFRunLoopWakeUp(loop);
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.01,false);require(!rows.count,@"perform block ignored its original mode");CFRunLoopRunInMode(custom,0.1,false);
        CFRunLoopRemoveSource(loop,keepAlive,custom);CFRunLoopSourceInvalidate(keepAlive);CFRelease(keepAlive);require(rows.count==1,@"perform block did not execute exactly once");return rows;
    }
    if(mode==5) {
        // Created outside observation: only actual entry may be claimed.
        DHFlowConfigure(NO,NO,1,1,nil,nil);self.timerRows=rows;self.timerMarker=[NSObject new];
        NSTimer *timer=[NSTimer timerWithTimeInterval:0.002 target:self selector:@selector(timerTick:) userInfo:self.timerMarker repeats:YES];self.expectedTimer=timer;
        CFRunLoopAddTimer(loop,(__bridge CFRunLoopTimerRef)timer,custom);
        DHFlowConfigureWithAPIs(YES,YES,16,10000,nil,@[@"IDHFlowTimerMode"],@[@"NSTimer.runloop-callback"]);CFRunLoopRunInMode(custom,0.1,false);[timer invalidate];
        require(rows.count==2 && [rows[0][@"kind"] isEqual:@"native-timer-original-target"] && [rows[1][@"kind"] isEqual:@"native-timer-original-target"] && !timer.valid,@"native timer original target/argument/invalidation changed");
        self.expectedTimer=nil;return rows;
    }
    if(mode>=6 && mode<=10) {
        self.timerRows=rows;self.timerMarker=[NSObject new];NSTimer *timer=nil;BOOL block=(mode==7 || mode==9),scheduled=(mode==8 || mode==9);
        if(block) {
            void (^body)(NSTimer *)=^(NSTimer *actual){timer_record(rows,actual==self.expectedTimer?@"factory-block-original-timer":@"factory-block-mismatch");if(rows.count==2)[actual invalidate];};
            timer=scheduled?[NSTimer scheduledTimerWithTimeInterval:0.002 repeats:YES block:body]:[NSTimer timerWithTimeInterval:0.002 repeats:YES block:body];
        } else timer=scheduled?[NSTimer scheduledTimerWithTimeInterval:0.002 target:self selector:@selector(timerTick:) userInfo:self.timerMarker repeats:YES]:[NSTimer timerWithTimeInterval:0.002 target:self selector:@selector(timerTick:) userInfo:self.timerMarker repeats:YES];
        self.expectedTimer=timer;
        if(mode==10){[timer fire];[timer fire];[timer invalidate];}
        else if(scheduled) {CFRunLoopRunInMode(custom,0.01,false);require(!rows.count,@"scheduled factory moved timer out of original default mode");CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.1,false);}
        else {CFRunLoopAddTimer(loop,(__bridge CFRunLoopTimerRef)timer,custom);CFRunLoopRunInMode(custom,0.1,false);}
        require(rows.count==2 && !timer.valid && fabs(timer.timeInterval-0.002)<1e-9,@"NSTimer factory changed interval, repeat count or invalidation");
        for(NSDictionary *row in rows)require([row[@"kind"] isEqual:block?@"factory-block-original-timer":@"native-timer-original-target"],@"NSTimer factory changed original callback argument/target/userInfo");
        self.expectedTimer=nil;return rows;
    }
    return rows;
}
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
    if(self.mode==7 || self.mode==9) {
        dispatch_group_t dependency=dispatch_group_create();self.notificationDependency=dependency;dispatch_group_enter(dependency);
        dispatch_group_enter(group);dispatch_group_enter(group);
        dispatch_group_notify(dependency,queue,^{[self normal:41];dispatch_group_leave(group);});
        dispatch_group_notify_f(dependency,queue,(__bridge_retained void *)self,function_body);
        require(dispatch_group_wait(group,DISPATCH_TIME_NOW)!=0,@"notify callback ran before dependency completion");
        if(self.mode==7)dispatch_group_leave(dependency);return 2;
    }
    if(self.mode==8) {
        dispatch_block_t dependency=dispatch_block_create(DISPATCH_BLOCK_BARRIER,^{[self normal:999];});
        dispatch_block_cancel(dependency);self.special=dependency;dispatch_group_enter(group);
        dispatch_block_t notification=dispatch_block_create_with_qos_class(0,QOS_CLASS_UTILITY,0,^{[self normal:42];dispatch_group_leave(group);});
        dispatch_block_notify(dependency,queue,notification);dispatch_async(queue,dependency);return 1;
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
static void check_source_rows(NSArray *rows,unsigned captured) {
    unsigned events=0,cancel=0,registration=0,identified=0;NSMutableSet *ids=[NSMutableSet set];
    for(NSDictionary *row in rows) {
        if([row[@"kind"] isEqual:@"event"])events++;
        if([row[@"kind"] isEqual:@"cancel"])cancel++;
        if([row[@"kind"] isEqual:@"registration"])registration++;
        if([row[@"task"] length]){identified++;[ids addObject:row[@"task"]];}
    }
    require(rows.count==4 && events==2 && cancel==1 && registration==1,@"source callback kinds/counts changed");
    require(identified==captured && ids.count==captured,@"source deliveries lost identity, were conflated or falsely associated");
}
static NSDictionary *source_context_tags(NSArray *rows) {
    NSMutableDictionary *result=[NSMutableDictionary dictionary];for(NSDictionary *row in rows) {
        NSMutableArray *values=result[row[@"kind"]];if(!values)result[row[@"kind"]]=values=[NSMutableArray array];[values addObject:row[@"tag"]];
    }return result;
}
NSDictionary *DHFlowSelfTest(void) {
    NSMutableArray *passed=[NSMutableArray array],*slots=[NSMutableArray array];NSMutableDictionary *result=[@{@"pass":@NO,@"restartRequired":@YES} mutableCopy];
    IDHFlowProbe *probe=[IDHFlowProbe new];probe.marker=[NSException exceptionWithName:@"IDH-original-marker" reason:@"fixture" userInfo:nil];probe.observations=[NSMutableArray array];
    probe.queue=dispatch_queue_create("com.iosdecrypthub.flow.fixture",DISPATCH_QUEUE_SERIAL);probe.group=dispatch_group_create();
    DHFlowSetOwnedFixtureScope(YES);
    @try {
        require(![DHLogStore shared].paused && ![[DHLogStore shared] isPausedForCategory:DHCategoryOther],@"resume all/other before selftest");
        dh_hook_options options;dh_thunk_options_default(&options);options.fixed_abi=1;options.capture_return=1;char error[512]={0};
        for(NSString *name in @[@"normal:",@"throwOut",@"jumpOut",@"cppOut",@"catchInside",@"schedule",@"exitOut",@"unverified",@"partial",@"sourceMode:",@"timerMode:"]) {
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
        unsigned notifyBefore=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];
        DHFlowConfigure(YES,NO,16,10000,nil,nil);probe.mode=7;[probe schedule];drain(probe);probe.mode=0;
        NSArray *notifyTasks=DHFlowRead(notifyBefore,16,0)[@"tasks"];
        require(notifyTasks.count==2 && probe.observations.count==2,@"group notify block/function changed callback/context count");
        NSMutableSet *notifyAPIs=[NSMutableSet set];for(NSDictionary *t in notifyTasks){[notifyAPIs addObject:t[@"api"]];require([t[@"state"] isEqual:@"completed"] && [t[@"asyncSubmittedByCallId"] length]>0,@"group notify lost observed submission/completion");}
        require([notifyAPIs isEqualToSet:[NSSet setWithArray:@[@"dispatch_group_notify",@"dispatch_group_notify_f"]]],@"group notify APIs not observed");
        for(NSDictionary *o in probe.observations)require([o[@"asyncTaskId"] length]>0,@"group notify callback lost task identity");
        [passed addObject:@"group-notify-block-and-function-preserve-dependency-context-once"];
        notifyBefore=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];
        DHFlowConfigure(YES,NO,16,10000,nil,nil);probe.mode=8;[probe schedule];drain(probe);probe.mode=0;
        notifyTasks=DHFlowRead(notifyBefore,16,0)[@"tasks"];NSDictionary *notification=notifyTasks.firstObject;
        require(notifyTasks.count==1 && probe.observations.count==1 && dispatch_block_testcancel(probe.special),@"block notify changed canceled dependency or callback count");
        require([notification[@"api"] isEqual:@"dispatch_block_notify"] && [notification[@"state"] isEqual:@"completed"] && [notification[@"dispatchBlockMetadataPreserved"] boolValue],@"block notify did not preserve public notification metadata/identity");
        require(dispatch_block_wait(probe.special,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"block notify changed dependency wait semantics");
        [passed addObject:@"block-notify-preserves-cancelled-dependency-and-special-notification"];
        notifyBefore=[DHFlowState()[@"retained"] unsignedIntValue];[probe.observations removeAllObjects];
        DHFlowConfigure(YES,NO,16,10000,nil,nil);probe.mode=9;[probe schedule];DHFlowConfigure(NO,NO,1,1,nil,nil);
        require([DHFlowState()[@"pendingOrRunning"] unsignedIntValue]==2,@"pending notifications were reported complete");
        dispatch_group_leave(probe.notificationDependency);drain(probe);probe.mode=0;
        notifyTasks=DHFlowRead(notifyBefore,16,0)[@"tasks"];require(notifyTasks.count==2 && probe.observations.count==2,@"disabling capture dropped pending notifications");
        for(NSDictionary *o in probe.observations)require([o[@"asyncTaskId"] length]>0,@"pending notification lost previously observed submission");
        [passed addObject:@"disable-retains-pending-notify-identity-until-original-dependency-completes"];
        unsigned sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue],registrationBefore=[DHFlowState()[@"retainedRegistrations"] unsignedIntValue];
        DHFlowConfigure(YES,NO,32,10000,nil,nil);check_source_rows([probe sourceMode:10],4);
        NSArray *sourceTasks=DHFlowRead(sourceBefore,32,0)[@"tasks"],*sourceRegistrations=DHFlowRegistrations(registrationBefore,8)[@"registrations"];
        require(sourceTasks.count==4 && sourceRegistrations.count==3,@"source registration was confused with enqueue/delivery");
        unsigned repeated=0;for(NSDictionary *r in sourceRegistrations)if([r[@"capturedInvocations"] unsignedIntValue]==2)repeated++;
        require(repeated==1,@"repeated source events did not share exactly one registration");
        for(NSDictionary *t in sourceTasks)require([t[@"edge"] isEqual:@"registered-handler-to-callback"] && [t[@"registrationId"] length]>0 && [t[@"state"] isEqual:@"completed"],@"source callback invented a submit edge or failed to complete");
        [passed addObject:@"source-block-registration-two-events-and-cancel-have-distinct-delivery-identities"];
        DHFlowConfigure(NO,NO,1,1,nil,nil);NSArray *sourceBaseline=[probe sourceMode:11];check_source_rows(sourceBaseline,0);
        DHFlowConfigure(YES,NO,32,10000,nil,nil);NSArray *sourceObserved=[probe sourceMode:12];check_source_rows(sourceObserved,4);
        require([source_context_tags(sourceBaseline) isEqual:source_context_tags(sourceObserved)],@"source function adapter changed the context libdispatch supplied");
        [passed addObject:@"source-function-context-matches-uninstrumented-registration-event-and-cancel"];
        for(NSNumber *mode in @[@13,@19]) {
            registrationBefore=[DHFlowState()[@"retainedRegistrations"] unsignedIntValue];DHFlowConfigure(YES,NO,32,10000,nil,nil);
            check_source_rows([probe sourceMode:mode.unsignedLongLongValue],4);sourceRegistrations=DHFlowRegistrations(registrationBefore,8)[@"registrations"];
            NSDictionary *retired=sourceRegistrations.firstObject;
            require(![retired[@"active"] boolValue] && ![retired[@"observedInvocations"] unsignedIntValue] && [retired[@"terminalReason"] hasPrefix:@"source-handler-"],@"replaced/removed source handler remained active or ran");
        }
        [passed addObject:@"source-function-replacement-and-null-removal-retire-original-registration"];
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,32,10000,nil,nil);check_source_rows([probe sourceMode:14],2);
        require([DHFlowState()[@"retained"] unsignedIntValue]==sourceBefore+2,@"special source handler metadata was wrapped or given a guessed edge");
        [passed addObject:@"source-special-event-block-keeps-original-metadata-and-explicitly-unobserved-edge"];
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];registrationBefore=[DHFlowState()[@"retainedRegistrations"] unsignedIntValue];DHFlowConfigure(YES,NO,32,10000,nil,nil);
        sourceObserved=[probe sourceMode:15];check_source_rows(sourceObserved,4);
        for(NSDictionary *row in sourceObserved)require([row[@"target"] unsignedLongLongValue]==0x345,@"source target queue behavior changed");
        for(NSDictionary *t in DHFlowRead(sourceBefore,32,0)[@"tasks"])require([t[@"queue"] isEqual:@"com.iosdecrypthub.flow.fixture.target"],@"source delivery retained stale target queue metadata");
        for(NSDictionary *r in DHFlowRegistrations(registrationBefore,8)[@"registrations"])require([r[@"queueAtRegistration"] isEqual:@"com.iosdecrypthub.flow.fixture"] && [r[@"currentKnownQueue"] isEqual:@"com.iosdecrypthub.flow.fixture.target"],@"source registration and updated target were conflated");
        [passed addObject:@"source-target-change-preserves-original-queue-execution-and-registration-history"];
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];uint64_t unknownBefore=[DHFlowState()[@"sourceAdapters"][@"unobservedSourceTargets"] unsignedLongLongValue];
        DHFlowConfigure(YES,NO,32,10000,nil,nil);check_source_rows([probe sourceMode:16],0);
        require([DHFlowState()[@"retained"] unsignedIntValue]==sourceBefore && [DHFlowState()[@"sourceAdapters"][@"unobservedSourceTargets"] unsignedLongLongValue]>unknownBefore,@"preexisting source target was guessed or original callbacks changed");
        [passed addObject:@"source-created-before-observation-forwards-without-guessed-target-or-parent"];
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,1,10000,nil,nil);check_source_rows([probe sourceMode:17],1);
        require([DHFlowState()[@"retained"] unsignedIntValue]==sourceBefore+1,@"source repeated delivery exceeded task budget");
        [passed addObject:@"source-budget-forwards-all-events-and-cancellation-without-unbounded-tasks"];
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,32,10000,nil,nil);check_source_rows([probe sourceMode:18],0);
        require([DHFlowState()[@"retained"] unsignedIntValue]==sourceBefore,@"disabled source registration falsely became a queued task");
        [passed addObject:@"disabled-source-capture-keeps-original-callbacks-without-fake-pending-tasks"];
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];
        DHFlowConfigureWithAPIs(YES,NO,32,10000,nil,nil,@[@"SOURCE_SET_EVENT"]);
        sourceObserved=[probe sourceMode:21];NSMutableArray *sourceOnly=[NSMutableArray array];NSDictionary *childRow=nil;
        for(NSDictionary *row in sourceObserved)if([row[@"kind"] isEqual:@"child"])childRow=row;else [sourceOnly addObject:row];
        check_source_rows(sourceOnly,2);require(sourceObserved.count==5 && [childRow[@"task"] length]>0,@"root API filter changed source callbacks or severed a GCD descendant");
        sourceTasks=DHFlowRead(sourceBefore,8,0)[@"tasks"];require(sourceTasks.count==3,@"root API filter captured unrelated source registration/cancel roots");
        for(NSDictionary *t in sourceTasks)if([t[@"api"] isEqual:@"dispatch_async"])require([t[@"asyncParentTaskId"] length]>0,@"API-selected source lost actual child task edge");
        sourceBefore=[DHFlowState()[@"retained"] unsignedIntValue];NSUInteger apiObserved=probe.observations.count;
        [probe schedule];drain(probe);
        require([DHFlowState()[@"retained"] unsignedIntValue]==sourceBefore && probe.observations.count==apiObserved+7 && [DHFlowState()[@"rootAPIMisses"] unsignedLongLongValue]>0,@"root API filter captured unrelated GCD roots or changed their original execution");
        [passed addObject:@"root-API-filter-is-case-insensitive-keeps-source-descendants-and-forwards-unmatched-roots"];
        DHFlowConfigure(NO,NO,1,1,nil,nil);NSArray *timerBaseline=[probe timerMode:1];
        unsigned baselineRetains=probe.timerContextRetains,baselineReleases=probe.timerContextReleases;
        require(timerBaseline.count==2 && ![timerBaseline[0][@"task"] length] && ![timerBaseline[1][@"task"] length],@"uncaptured timer baseline acquired a task");
        unsigned timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];
        DHFlowConfigure(YES,NO,32,10000,nil,nil);NSArray *timerRows=[probe timerMode:1];
        require(probe.timerContextRetains==baselineRetains && probe.timerContextReleases==baselineReleases,@"CF timer context ownership differs from the same uncaptured repeat sequence");
        require(timerRows.count==2 && [timerRows[0][@"task"] length]>0 && [timerRows[1][@"task"] length]>0 && ![timerRows[0][@"task"] isEqual:timerRows[1][@"task"]],@"CF repeat deliveries lost distinct task identities");
        for(NSDictionary *row in timerRows)require([row[@"mode"] isEqual:@"IDHFlowTimerMode"],@"CF repeat callback ran in wrong mode");
        require([DHFlowState()[@"retained"] unsignedIntValue]==timerBefore+2,@"CF timer created phantom enqueues or missed real deliveries");
        [passed addObject:@"CF-timer-original-context-retain-release-repeat-and-runloop-mode-preserved"];
        timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,32,10000,nil,nil);[probe timerMode:2];
        require([DHFlowState()[@"retained"] unsignedIntValue]==timerBefore,@"removed/invalid timer falsely became a pending delivery");
        [passed addObject:@"CF-timer-removal-and-invalidation-do-not-invent-delivery-tasks"];
        DHFlowConfigure(YES,NO,32,10000,nil,nil);timerRows=[probe timerMode:3];
        require([timerRows.firstObject[@"task"] length]>0 && [timerRows.firstObject[@"kind"] isEqual:@"cf-handler-original-timer"],@"CF handler argument or task identity changed");
        [passed addObject:@"CF-timer-handler-keeps-original-timer-and-one-shot-invalidation"];
        timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,32,10000,nil,nil);timerRows=[probe timerMode:4];
        NSArray *performTasks=DHFlowRead(timerBefore,4,0)[@"tasks"];
        require([timerRows.firstObject[@"task"] length]>0 && performTasks.count==1 && [performTasks.firstObject[@"api"] isEqual:@"CFRunLoopPerformBlock"] && [performTasks.firstObject[@"edge"] isEqual:@"observed-submit-to-execute"],@"runloop block mode/submission/execution identity changed");
        [passed addObject:@"RunLoop-perform-block-preserves-mode-and-actual-single-queue-edge"];
        if([DHFlowTimerState()[@"nativeEntryReady"] boolValue]) {
            timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];timerRows=[probe timerMode:5];
            NSArray *nativeTasks=DHFlowRead(timerBefore,8,0)[@"tasks"];require(nativeTasks.count==2,@"native timer entries were lost or counted twice");
            for(NSDictionary *row in timerRows)require([row[@"task"] length]>0,@"old timer actual entry not observed");
            for(NSDictionary *task in nativeTasks)require([task[@"edge"] isEqual:@"observed-callback-entry; registration-unobserved"] && ![task[@"registrationId"] length] && ![task[@"asyncSubmittedByCallId"] length] && [task[@"asyncEnteredByCallId"] length]>0,@"old timer fabricated registration or submission history");
            [passed addObject:@"native-Foundation-timer-entry-ABI-calibrated-without-fake-prewindow-registration"];
        } else result[@"skipped"]=@[@{@"fixture":@"native-Foundation-timer-entry",@"reason":DHFlowTimerState()[@"nativeEntryReason"]}];
        if([DHFlowTimerState()[@"factoriesReady"] boolValue]) {
            for(NSNumber *mode in @[@6,@7,@8,@9]) {
                timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];unsigned registrationStart=[DHFlowState()[@"retainedRegistrations"] unsignedIntValue];
                DHFlowConfigureWithCallbacks(YES,NO,16,10000,nil,nil,nil,@[@"IDHFlowProbe timerTick:",@"NSTimer.block"]);timerRows=[probe timerMode:mode.unsignedLongLongValue];
                NSArray *tasks=DHFlowRead(timerBefore,8,0)[@"tasks"],*registrations=DHFlowRegistrations(registrationStart,8)[@"registrations"];
                require(tasks.count==2 && registrations.count==1 && [registrations.firstObject[@"capturedInvocations"] unsignedIntValue]==2,@"NSTimer factory double-registered an internal CF create or conflated repeats");
                for(NSDictionary *row in timerRows)require([row[@"task"] length]>0,@"registered NSTimer callback lost task identity");
                for(NSDictionary *task in tasks)require([task[@"edge"] isEqual:@"registered-handler-to-callback"] && [task[@"registrationId"] length]>0,@"registered NSTimer delivery fabricated an enqueue");
            }
            [passed addObject:@"NSTimer-target-block-scheduled-and-unscheduled-factories-preserve-registration-mode-and-original-behavior"];
            timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];unsigned registrationBefore=[DHFlowState()[@"retainedRegistrations"] unsignedIntValue];
            DHFlowConfigureWithCallbacks(YES,NO,16,10000,nil,nil,nil,@[@"IDHNoSuchTimerTarget"]);timerRows=[probe timerMode:6];
            require(timerRows.count==2 && [DHFlowState()[@"retained"] unsignedIntValue]==timerBefore && [DHFlowState()[@"retainedRegistrations"] unsignedIntValue]==registrationBefore && [DHFlowState()[@"rootCallbackMisses"] unsignedLongLongValue]>0,@"timer callback label filter changed original execution or accepted unknown root");
            [passed addObject:@"timer-target-selector-root-filter-preserves-original-callback"];
            timerBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,16,10000,nil,nil);timerRows=[probe timerMode:10];
            require([DHFlowState()[@"retained"] unsignedIntValue]==timerBefore,@"manual fire was misreported as scheduled runtime callback");
            for(NSDictionary *row in timerRows)require(![row[@"task"] length],@"manual fire invented asynchronous context");
            [passed addObject:@"NSTimer-manual-fire-stays-synchronous-and-is-not-a-scheduled-delivery"];
        } else {
            NSMutableArray *skipped=[result[@"skipped"] mutableCopy]?:[NSMutableArray array];[skipped addObject:@{@"fixture":@"NSTimer-factory-correlation",@"reason":DHFlowTimerState()[@"factoryReason"]}];result[@"skipped"]=skipped;
        }
        unsigned internalBefore=[DHFlowState()[@"retained"] unsignedIntValue];DHFlowConfigure(YES,NO,8,10000,nil,nil);NSArray *internalRows=[probe timerMode:11];
        require(internalRows.count==1 && ![internalRows[0][@"task"] length] && [DHFlowState()[@"retained"] unsignedIntValue]==internalBefore,@"Agent internal work inherited an App post/async context");
        [passed addObject:@"Agent-internal-dispatch-stays-excluded-even-inside-observed-post"];
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
    @finally {jumpTarget=NULL;[DHLogStore shared].paused=NO;DHFlowConfigure(NO,NO,1,1,nil,nil);DHFlowSetOwnedFixtureScope(NO);for(NSNumber *slot in slots)dh_thunk_disable(slot.intValue);}
    result[@"passed"]=passed;result[@"slots"]=slots;result[@"state"]=DHFlowState();return result;
}
