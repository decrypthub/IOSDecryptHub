#import "dh_flow_operations.h"
#import "dh_flow.h"
#import "dh_thunk.h"
#import "dh_event.h"
#include "dh_health.h"
#include <objc/runtime.h>
#include <pthread.h>
#include <stdatomic.h>
#include <ptrauth.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {OP_BINDINGS=64,OP_BLOCKS=128,OP_METHODS=32};
static pthread_mutex_t operationLock=PTHREAD_MUTEX_INITIALIZER;
static const char operationKey,blocksKey;
static unsigned bindingCount,blockCount,methodCount;
static _Atomic int ready;
static _Atomic int blockInvokersReady;
static _Atomic uint64_t rejectedBindings,unknownBlocks;
static _Atomic uintptr_t calibrationPC[2];
static uint64_t invokerStart[2],invokerEnd[2];
static char prepareReason[256]="not prepared";
static char lastBindingError[256];
static void *fixedOriginals[5];
static Method fixedMethods[5],runMethods[OP_METHODS];
static void *runOriginals[OP_METHODS];

@class DHOperationBinding;
@interface DHOperationBlock:NSObject {
@public __weak NSOperation *operation;__weak DHOperationBinding *binding;__weak id wrapper;dispatch_block_t original;uint64_t task;unsigned entries,workerIndex;BOOL executedBeforePublication;
}
@end
@implementation DHOperationBlock
- (void)dealloc {DHFlowUnresolvedOneShot(task,"operation-block-released-without-observed-execution");}
@end
@interface DHOperationBinding:NSObject {
@public __weak NSOperation *operation;uint64_t identifier,startTask,submitted,sampled;unsigned startEntries,mainEntries;
    BOOL accepted,returned,threw,asynchronous,cancelled,finished,executing,useMain;
    char queue[128],className[128],name[128],reason[192];
    uint64_t workerTasks[OP_BLOCKS];unsigned workerEntries[OP_BLOCKS],workerCount;
}
@end
@implementation DHOperationBinding
- (void)dealloc {DHFlowUnresolvedOneShot(startTask,"operation-released-without-observed-start");}
@end
static DHOperationBinding *observed[OP_BINDINGS]; // bounded history; operation itself remains weak
static NSString *text(const char *bytes) {return [[NSString alloc] initWithBytes:bytes length:strlen(bytes) encoding:NSUTF8StringEncoding]?:@"<invalid-or-truncated-UTF8>";}
static unsigned copy_workers(DHOperationBinding *binding,uint64_t tokens[OP_BLOCKS],unsigned *entries) {
    pthread_mutex_lock(&operationLock);unsigned count=binding->workerCount;
    memcpy(tokens,binding->workerTasks,count*sizeof(*tokens));if(entries)memcpy(entries,binding->workerEntries,count*sizeof(*entries));
    pthread_mutex_unlock(&operationLock);return count;
}

static void snapshot(DHOperationBinding *binding,NSOperation *operation) {
    // Public, thread-safe lifecycle accessors; never call application code while
    // holding our lock. A start() return does not prove asynchronous completion.
    BOOL a=operation.asynchronous,c=operation.cancelled,f=operation.finished,e=operation.executing;
    uint64_t sampled=DHMonotonicNS();pthread_mutex_lock(&operationLock);binding->asynchronous=a;binding->cancelled=c;binding->finished=f;binding->executing=e;binding->sampled=sampled;
    BOOL missed=f && !(binding->useMain?binding->mainEntries:binding->startEntries);pthread_mutex_unlock(&operationLock);
    if(missed)DHFlowUnresolvedOneShot(binding->startTask,"operation-finished-without-observed-execution");
    if(f) {
        uint64_t tokens[OP_BLOCKS];unsigned entries[OP_BLOCKS],count=copy_workers(binding,tokens,entries);
        for(unsigned i=0;i<count;i++)if(!entries[i])DHFlowUnresolvedOneShot(tokens[i],"operation-finished-without-observed-block");
    }
}
typedef void (*RunMethod)(__unsafe_unretained id,SEL);
static void run_method(unsigned index,__unsafe_unretained NSOperation *operation,SEL command) {
    RunMethod original=(RunMethod)__atomic_load_n(&runOriginals[index],__ATOMIC_ACQUIRE);
    DHOperationBinding *binding=objc_getAssociatedObject(operation,&operationKey);
    if(!binding){original(operation,command);return;}
    int entry=errno;BOOL isStart=command==@selector(start);
    pthread_mutex_lock(&operationLock);if(isStart)binding->startEntries++;else binding->mainEntries++;pthread_mutex_unlock(&operationLock);
    BOOL selected=binding->useMain?!isStart:isStart;
    // The prepared task's once-only claim also handles nested super calls. Do
    // not introduce a second TLS scope that longjmp could leave stale.
    dispatch_block_t invoke=^{original(operation,command);};
    BOOL normal=NO;errno=entry;
    @try {if(selected)DHFlowRunPreparedOneShot(binding->startTask,invoke);else original(operation,command);normal=YES;}
    @finally {
        int final=errno;pthread_mutex_lock(&operationLock);if(isStart){binding->returned=normal;binding->threw=!normal;}pthread_mutex_unlock(&operationLock);
        // Never let diagnostic property access replace the original exception.
        @try {snapshot(binding,operation);}@catch(NSException *error){(void)error;}
        errno=final;
    }
}
#define DH_OPERATION_RUN(N) static void run_##N(__unsafe_unretained NSOperation *o,SEL c){run_method(N,o,c);}
DH_OPERATION_RUN(0) DH_OPERATION_RUN(1) DH_OPERATION_RUN(2) DH_OPERATION_RUN(3)
DH_OPERATION_RUN(4) DH_OPERATION_RUN(5) DH_OPERATION_RUN(6) DH_OPERATION_RUN(7)
DH_OPERATION_RUN(8) DH_OPERATION_RUN(9) DH_OPERATION_RUN(10) DH_OPERATION_RUN(11)
DH_OPERATION_RUN(12) DH_OPERATION_RUN(13) DH_OPERATION_RUN(14) DH_OPERATION_RUN(15)
DH_OPERATION_RUN(16) DH_OPERATION_RUN(17) DH_OPERATION_RUN(18) DH_OPERATION_RUN(19)
DH_OPERATION_RUN(20) DH_OPERATION_RUN(21) DH_OPERATION_RUN(22) DH_OPERATION_RUN(23)
DH_OPERATION_RUN(24) DH_OPERATION_RUN(25) DH_OPERATION_RUN(26) DH_OPERATION_RUN(27)
DH_OPERATION_RUN(28) DH_OPERATION_RUN(29) DH_OPERATION_RUN(30) DH_OPERATION_RUN(31)
#define DH_OPERATION_PTR(N) (void *)run_##N
static void *runReplacements[OP_METHODS]={
    DH_OPERATION_PTR(0),DH_OPERATION_PTR(1),DH_OPERATION_PTR(2),DH_OPERATION_PTR(3),
    DH_OPERATION_PTR(4),DH_OPERATION_PTR(5),DH_OPERATION_PTR(6),DH_OPERATION_PTR(7),
    DH_OPERATION_PTR(8),DH_OPERATION_PTR(9),DH_OPERATION_PTR(10),DH_OPERATION_PTR(11),
    DH_OPERATION_PTR(12),DH_OPERATION_PTR(13),DH_OPERATION_PTR(14),DH_OPERATION_PTR(15),
    DH_OPERATION_PTR(16),DH_OPERATION_PTR(17),DH_OPERATION_PTR(18),DH_OPERATION_PTR(19),
    DH_OPERATION_PTR(20),DH_OPERATION_PTR(21),DH_OPERATION_PTR(22),DH_OPERATION_PTR(23),
    DH_OPERATION_PTR(24),DH_OPERATION_PTR(25),DH_OPERATION_PTR(26),DH_OPERATION_PTR(27),
    DH_OPERATION_PTR(28),DH_OPERATION_PTR(29),DH_OPERATION_PTR(30),DH_OPERATION_PTR(31)};
static int ensure_run_method(Method method,char error[256]) {
    if(!method || method_getNumberOfArguments(method)!=2){strlcpy(error,"operation execution Method must have exactly self/_cmd",256);return -1;}
    char *type=method_copyReturnType(method);BOOL valid=type && !strcmp(type,"v");free(type);
    if(!valid){strlcpy(error,"operation execution Method must return void",256);return -1;}
    pthread_mutex_lock(&operationLock);
    for(unsigned i=0;i<methodCount;i++)if(runMethods[i]==method){pthread_mutex_unlock(&operationLock);return (int)i;}
    if(methodCount==OP_METHODS){strlcpy(error,"operation execution Method capacity exhausted",256);pthread_mutex_unlock(&operationLock);return -1;}
    unsigned index=methodCount;
    dh_method_adapter_spec spec={method,runReplacements[index],&runOriginals[index],"NSOperation execution"};
    int status=dh_thunk_install_method_adapters(&spec,1,error,256);
    if(!status){runMethods[index]=method;methodCount++;}
    pthread_mutex_unlock(&operationLock);return status?status:(int)index;
}
static NSMutableArray *block_records(NSOperation *operation,BOOL create) {
    NSMutableArray *records=objc_getAssociatedObject(operation,&blocksKey);
    if(!records && create){records=[NSMutableArray array];objc_setAssociatedObject(operation,&blocksKey,records,OBJC_ASSOCIATION_RETAIN_NONATOMIC);}
    return records;
}
static dispatch_block_t wrap_block(__unsafe_unretained dispatch_block_t body,DHOperationBlock **output) {
    if(!body || !atomic_load(&ready) || !atomic_load(&blockInvokersReady) || !DHFlowCallbackCaptureActive())return body;
    uintptr_t callback=DHFlowCallbackBlockAddress(body);
    if(!callback){atomic_fetch_add(&unknownBlocks,1);return body;}
    pthread_mutex_lock(&operationLock);BOOL bounded=blockCount<OP_BLOCKS;if(bounded)blockCount++;pthread_mutex_unlock(&operationLock);
    if(!bounded){atomic_fetch_add(&rejectedBindings,1);return body;}
    DHOperationBlock *record=[DHOperationBlock new];record->original=[body copy];
    dispatch_block_t wrapper=[^{
        int saved=errno;uintptr_t lr=(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address),pc=lr>=4?lr-4:0;
        BOOL invoker=NO;for(unsigned i=0;i<2;i++)invoker|=pc>=invokerStart[i] && pc<invokerEnd[i];
        NSOperation *operation=record->operation;BOOL executing=NO;
        @try {executing=operation.executing;}@catch(NSException *error){(void)error;}
        pthread_mutex_lock(&operationLock);DHOperationBinding *binding=record->binding;record->entries++;uint64_t task=record->task;if(!task && invoker && executing)record->executedBeforePublication=YES;if(binding && record->workerIndex<binding->workerCount)binding->workerEntries[record->workerIndex]++;pthread_mutex_unlock(&operationLock);
        if(task && (!invoker || !executing)){DHFlowUnresolvedOneShot(task,"operation-block-outside-calibrated-execution");task=0;}
        errno=saved;DHFlowRunPreparedOneShot(task,record->original);
    } copy];
    record->wrapper=wrapper;*output=record;return wrapper;
}
static void attach_block(NSOperation *operation,DHOperationBlock *record,void *caller) {
    if(!operation || !record)return;record->operation=operation;
    pthread_mutex_lock(&operationLock);[block_records(operation,YES) addObject:record];pthread_mutex_unlock(&operationLock);
    DHOperationBinding *binding=objc_getAssociatedObject(operation,&operationKey);
    if(binding) {
        uintptr_t pc=DHFlowCallbackBlockAddress(record->original);char label[192];snprintf(label,sizeof(label),"%s.executionBlock",binding->className);
        uint64_t token=DHFlowPrepareOneShot("NSBlockOperation.addExecutionBlock",binding->queue,caller,(void *)pc,label);
        pthread_mutex_lock(&operationLock);record->task=token;record->binding=binding;record->workerIndex=binding->workerCount;binding->workerTasks[binding->workerCount]=token;binding->workerEntries[binding->workerCount++]=record->entries;BOOL missed=record->executedBeforePublication;pthread_mutex_unlock(&operationLock);
        if(missed)DHFlowUnresolvedOneShot(token,"operation-block-executed-before-binding-publication");
    }
}
static DHOperationBinding *observe_operation(NSOperation *operation,NSOperationQueue *queue,void *caller) {
    if(!operation || !atomic_load(&ready) || !DHFlowCallbackCaptureActive() || ![operation isKindOfClass:NSOperation.class])return nil;
    DHOperationBinding *old=objc_getAssociatedObject(operation,&operationKey);
    if(old) {
        pthread_mutex_lock(&operationLock);BOOL ambiguous=!old->accepted && !strcmp(old->reason,"enqueue-threw");pthread_mutex_unlock(&operationLock);
        if(ambiguous){uint64_t tokens[OP_BLOCKS];unsigned count=copy_workers(old,tokens,NULL);DHFlowUnresolvedOneShot(old->startTask,"operation-resubmission-after-throw-is-ambiguous");for(unsigned i=0;i<count;i++)DHFlowUnresolvedOneShot(tokens[i],"operation-resubmission-after-throw-is-ambiguous");}
        return nil;
    }
    Class cls=object_getClass(operation);char error[256]={0};Method start=class_getInstanceMethod(cls,@selector(start)),main=class_getInstanceMethod(cls,@selector(main));
    // An override can perform the entire synchronous operation in start() and
    // never call main(), even with false asynchronous/concurrent flags. Observe
    // the actual override; inherited Foundation start may use a private queue
    // entry, so use main() for that case. Lifecycle flags remain separate data.
    BOOL useMain=start==class_getInstanceMethod(NSOperation.class,@selector(start));
    int startIndex=ensure_run_method(start,error),mainIndex=startIndex>=0?ensure_run_method(main,error):-1;
    if(startIndex<0 || mainIndex<0){atomic_fetch_add(&rejectedBindings,1);pthread_mutex_lock(&operationLock);strlcpy(lastBindingError,error,sizeof(lastBindingError));pthread_mutex_unlock(&operationLock);return nil;}
    char label[192],queueLabel[128];snprintf(label,sizeof(label),"[%s %s]",class_getName(cls),useMain?"main":"start");
    snprintf(queueLabel,sizeof(queueLabel),"operation:%s",queue.name.UTF8String?:"<unnamed>");
    void *callback=__atomic_load_n(&runOriginals[useMain?mainIndex:startIndex],__ATOMIC_ACQUIRE);
    uint64_t token=DHFlowPrepareOneShot(useMain?"NSOperation.main":"NSOperation.start",queueLabel,caller,callback,label);if(!token)return nil;
    DHOperationBinding *binding=[DHOperationBinding new];binding->operation=operation;binding->startTask=token;binding->submitted=DHMonotonicNS();binding->useMain=useMain;
    strlcpy(binding->queue,queueLabel,sizeof(binding->queue));strlcpy(binding->className,class_getName(cls),sizeof(binding->className));
    strlcpy(binding->name,operation.name.UTF8String?:"",sizeof(binding->name));
    pthread_mutex_lock(&operationLock);
    if(bindingCount==OP_BINDINGS){pthread_mutex_unlock(&operationLock);atomic_fetch_add(&rejectedBindings,1);DHFlowUnresolvedOneShot(token,"operation-binding-capacity");return nil;}
    binding->identifier=bindingCount+1;observed[bindingCount++]=binding;pthread_mutex_unlock(&operationLock);
    objc_setAssociatedObject(operation,&operationKey,binding,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    pthread_mutex_lock(&operationLock);NSArray *records=[block_records(operation,NO) copy];pthread_mutex_unlock(&operationLock);
    for(DHOperationBlock *record in records) {
        uintptr_t pc=DHFlowCallbackBlockAddress(record->original);
        char workerLabel[192];snprintf(workerLabel,sizeof(workerLabel),"%s.executionBlock",class_getName(cls));
        uint64_t child=DHFlowPrepareOneShot("NSBlockOperation.executionBlock",queueLabel,caller,(void *)pc,workerLabel);
        pthread_mutex_lock(&operationLock);record->task=child;record->binding=binding;record->workerIndex=binding->workerCount;binding->workerTasks[binding->workerCount++]=child;pthread_mutex_unlock(&operationLock);
    }
    @try {snapshot(binding,operation);}@catch(NSException *error){(void)error;}
    return binding;
}
typedef void (*AddOperation)(__unsafe_unretained id,SEL,__unsafe_unretained NSOperation *);
typedef void (*AddOperations)(__unsafe_unretained id,SEL,__unsafe_unretained NSArray *,BOOL);
typedef void (*AddBlock)(__unsafe_unretained id,SEL,__unsafe_unretained dispatch_block_t);
typedef id (*BlockFactory)(__unsafe_unretained id,SEL,__unsafe_unretained dispatch_block_t);
static void accepted(DHOperationBinding *binding,BOOL good) {
    if(!binding)return;pthread_mutex_lock(&operationLock);binding->accepted=good;if(!good)strlcpy(binding->reason,"enqueue-threw",sizeof(binding->reason));pthread_mutex_unlock(&operationLock);
    // A custom queue may enqueue work and then throw. The exception alone is
    // not proof that a pending callback will never run.
}
static void queue_add(__unsafe_unretained NSOperationQueue *queue,SEL command,__unsafe_unretained NSOperation *operation) {
    int saved=errno;DHOperationBinding *binding=observe_operation(operation,queue,__builtin_return_address(0));BOOL normal=NO;errno=saved;
    @try {((AddOperation)__atomic_load_n(&fixedOriginals[0],__ATOMIC_ACQUIRE))(queue,command,operation);normal=YES;}
    @finally {int final=errno;accepted(binding,normal);errno=final;}
}
static void queue_add_many(__unsafe_unretained NSOperationQueue *queue,SEL command,__unsafe_unretained NSArray *operations,BOOL wait) {
    int saved=errno;NSMutableArray *bindings=[NSMutableArray array];
    if(atomic_load(&ready) && DHFlowCallbackCaptureActive() && [operations isKindOfClass:NSArray.class])
        for(NSUInteger i=0;i<MIN(operations.count,64);i++){DHOperationBinding *binding=observe_operation(operations[i],queue,__builtin_return_address(0));if(binding)[bindings addObject:binding];}
    BOOL normal=NO;errno=saved;
    @try {((AddOperations)__atomic_load_n(&fixedOriginals[1],__ATOMIC_ACQUIRE))(queue,command,operations,wait);normal=YES;}
    @finally {int final=errno;for(DHOperationBinding *binding in bindings)accepted(binding,normal);errno=final;}
}
static void queue_add_block(__unsafe_unretained NSOperationQueue *queue,SEL command,__unsafe_unretained dispatch_block_t body) {
    AddBlock original=(AddBlock)__atomic_load_n(&fixedOriginals[2],__ATOMIC_ACQUIRE);
    if(!atomic_load(&ready) || !DHFlowCallbackCaptureActive()){original(queue,command,body);return;}
    int saved=errno;char label[128];snprintf(label,sizeof(label),"operation:%s",queue.name.UTF8String?:"<unnamed>");
    dispatch_block_t wrapped=DHFlowWrapOneShot("NSOperationQueue.addOperationWithBlock",label,__builtin_return_address(0),body);
    DHFlowAdapterInternalBegin();errno=saved;
    @try {original(queue,command,wrapped);}@finally {int final=errno;DHFlowAdapterInternalEnd();errno=final;}
}
static id block_factory(__unsafe_unretained id cls,SEL command,__unsafe_unretained dispatch_block_t body) {
    int saved=errno;DHOperationBlock *record=nil;dispatch_block_t wrapped=wrap_block(body,&record);id operation=nil;DHFlowAdapterInternalBegin();errno=saved;
    @try {operation=((BlockFactory)__atomic_load_n(&fixedOriginals[3],__ATOMIC_ACQUIRE))(cls,command,wrapped);}
    @finally {saved=errno;DHFlowAdapterInternalEnd();errno=saved;}
    attach_block(operation,record,__builtin_return_address(0));errno=saved;return operation;
}
static void block_add(__unsafe_unretained NSOperation *operation,SEL command,__unsafe_unretained dispatch_block_t body) {
    int saved=errno;DHOperationBlock *record=nil;dispatch_block_t wrapped=wrap_block(body,&record);errno=saved;
    ((AddBlock)__atomic_load_n(&fixedOriginals[4],__ATOMIC_ACQUIRE))(operation,command,wrapped);int final=errno;
    attach_block(operation,record,__builtin_return_address(0));errno=final;
}
void DHFlowOperationPrepare(void) {
    if(atomic_load(&ready))return;
    const char *names[]={"addOperation:","addOperations:waitUntilFinished:","addOperationWithBlock:","blockOperationWithBlock:","addExecutionBlock:"};
    void *replacements[]={(void *)queue_add,(void *)queue_add_many,(void *)queue_add_block,(void *)block_factory,(void *)block_add};
    dh_method_adapter_spec specs[5];
    for(unsigned i=0;i<5;i++) {
        Method method=i==3?class_getClassMethod(NSBlockOperation.class,sel_registerName(names[i])):class_getInstanceMethod(i<3?NSOperationQueue.class:NSBlockOperation.class,sel_registerName(names[i]));
        fixedMethods[i]=method;specs[i]=(dh_method_adapter_spec){method,replacements[i],&fixedOriginals[i],"NSOperation scheduling"};
    }
    char reason[256]={0};int status=dh_thunk_install_method_adapters(specs,5,reason,sizeof(reason));
    if(!status) {
        // Discover actual Foundation block invokers in this process. Neither a
        // caller's direct executionBlocks invocation nor an arbitrary dispatch
        // of that block may steal the pending operation's execution identity.
        @try {
            NSOperationQueue *queue=[NSOperationQueue new];queue.name=@"com.iosdecrypthub.operation.calibration";queue.maxConcurrentOperationCount=2;
            NSBlockOperation *probe=[NSBlockOperation blockOperationWithBlock:^{atomic_store(&calibrationPC[0],(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address));}];
            [probe addExecutionBlock:^{atomic_store(&calibrationPC[1],(uintptr_t)ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address));}];
            [queue addOperation:probe];[queue waitUntilAllOperationsAreFinished];BOOL valid=YES;
            for(unsigned i=0;i<2;i++){uintptr_t pc=atomic_load(&calibrationPC[i]);valid&=pc>=4 && dh_unwind_bounds(pc-4,&invokerStart[i],&invokerEnd[i]);}
            atomic_store(&blockInvokersReady,valid);
        }@catch(NSException *error){(void)error;}
        strlcpy(reason,atomic_load(&blockInvokersReady)?"typed public queue/block adapters and actual block invokers ready":"queue/start adapters ready; block invoker calibration unavailable, original blocks retained",sizeof(reason));
    }
    pthread_mutex_lock(&operationLock);strlcpy(prepareReason,reason,sizeof(prepareReason));if(!status)atomic_store(&ready,1);pthread_mutex_unlock(&operationLock);
}
NSDictionary *DHFlowOperationState(void) {
    NSMutableArray *bindings=[NSMutableArray array],*rows=[NSMutableArray array];
    char lastError[256],reason[256];pthread_mutex_lock(&operationLock);for(unsigned i=0;i<bindingCount;i++){DHOperationBinding *binding=observed[i];if(binding)[bindings addObject:binding];}unsigned methods=methodCount,blocks=blockCount,created=bindingCount;BOOL prepared=atomic_load(&ready);strlcpy(lastError,lastBindingError,sizeof(lastError));strlcpy(reason,prepareReason,sizeof(reason));pthread_mutex_unlock(&operationLock);
    for(DHOperationBinding *binding in bindings) {
        NSOperation *operation=binding->operation;NSString *readError=@"";
        if(operation)@try {snapshot(binding,operation);}@catch(NSException *error){readError=error.name?:@"lifecycle-read-failed";}
        uint64_t tokens[OP_BLOCKS];unsigned entries[OP_BLOCKS],count=copy_workers(binding,tokens,entries);
        if(!operation){DHFlowUnresolvedOneShot(binding->startTask,"operation-object-released-without-observed-execution");for(unsigned i=0;i<count;i++)DHFlowUnresolvedOneShot(tokens[i],"operation-object-released-without-observed-block");}
        NSMutableArray *workers=[NSMutableArray array];for(unsigned i=0;i<count;i++)[workers addObject:@{@"taskId":DHFlowFields(tokens[i])[@"asyncTaskId"],@"observedEntries":@(entries[i])}];
        NSString *taskID=DHFlowFields(binding->startTask)[@"asyncTaskId"];
        pthread_mutex_lock(&operationLock);
        NSDictionary *row=@{@"operationId":[NSString stringWithFormat:@"%@:operation:%llu",DHProcessGeneration(),binding->identifier],@"submittedNs":[NSString stringWithFormat:@"%llu",binding->submitted],@"lifecycleSampleNs":[NSString stringWithFormat:@"%llu",binding->sampled],@"lifecycleObservation":operation?(readError.length?@"read-failed; previous-sample":@"current-public-read"):@"last-sample; object-released",@"class":text(binding->className),@"name":text(binding->name),@"queue":text(binding->queue),@"operationAlive":@(operation!=nil),@"executionTaskId":taskID,@"executionMethod":binding->useMain?@"main":@"start",@"enqueueReturned":@(binding->accepted),@"startEntries":@(binding->startEntries),@"mainEntries":@(binding->mainEntries),@"startReturned":@(binding->returned),@"startThrew":@(binding->threw),@"isAsynchronous":@(binding->asynchronous),@"isCancelled":@(binding->cancelled),@"isFinished":@(binding->finished),@"isExecuting":@(binding->executing),@"reason":text(binding->reason),@"lifecycleReadError":readError,@"workers":workers};pthread_mutex_unlock(&operationLock);[rows addObject:row];
    }
    return @{@"processGeneration":DHProcessGeneration(),@"ready":@(prepared),@"blockInvokersReady":@((BOOL)atomic_load(&blockInvokersReady)),@"reason":@(reason),@"lastBindingError":text(lastError),@"bindingCapacity":@64,@"bindingsCreated":@(created),@"executionMethodCapacity":@32,@"executionMethods":@(methods),@"blockCapacity":@128,@"blocksCreated":@(blocks),@"rejectedBindings":@(atomic_load(&rejectedBindings)),@"unwrappedBlocks":@(atomic_load(&unknownBlocks)),@"operations":rows,@"semantics":@"tasks describe actual main/start/block callbacks; public lifecycle is separately sampled; start return does not imply operation finished; executionBlocks contains forwarding blocks for wrapped callbacks"};
}
