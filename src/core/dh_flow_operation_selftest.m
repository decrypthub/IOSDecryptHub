#import "dh_flow_operations.h"
#import "dh_flow.h"
#import "dh_call_context.h"
#include <unistd.h>

static void require(BOOL good,NSString *message) {if(!good)[NSException raise:@"IDHOperationFixture" format:@"%@",message];}
static void record(NSMutableArray *rows,NSString *label) {@synchronized(rows){[rows addObject:@{@"label":label,@"taskId":DHFlowFields(dh_call_async())[@"asyncTaskId"]}];}}
@interface IDHOperationSync:NSOperation
@property(copy) dispatch_block_t body;
@end
@implementation IDHOperationSync
- (void)main {if(self.body)self.body();}
@end
@interface IDHOperationOwnStart:NSOperation {BOOL _working,_done;}
@property(copy) dispatch_block_t body;
@property unsigned mainCalls;
@end
@implementation IDHOperationOwnStart
- (BOOL)isExecuting {@synchronized(self){return _working;}}
- (BOOL)isFinished {@synchronized(self){return _done;}}
- (void)main {self.mainCalls++;}
- (void)start {
    [self willChangeValueForKey:@"isExecuting"];@synchronized(self){_working=YES;}[self didChangeValueForKey:@"isExecuting"];
    if(self.body)self.body();
    [self willChangeValueForKey:@"isExecuting"];[self willChangeValueForKey:@"isFinished"];
    @synchronized(self){_working=NO;_done=YES;}
    [self didChangeValueForKey:@"isFinished"];[self didChangeValueForKey:@"isExecuting"];
}
@end
@interface IDHOperationAsync:NSOperation {
    BOOL _working,_done;
}
@property(strong) dispatch_semaphore_t started;
@property(strong) dispatch_semaphore_t gate;
@property(strong) dispatch_queue_t worker;
@property(strong) NSMutableArray *rows;
@end
@implementation IDHOperationAsync
- (BOOL)isAsynchronous {return YES;}
- (BOOL)isExecuting {@synchronized(self){return _working;}}
- (BOOL)isFinished {@synchronized(self){return _done;}}
- (void)start {
    record(self.rows,@"async-start");
    [self willChangeValueForKey:@"isExecuting"];@synchronized(self){_working=YES;}[self didChangeValueForKey:@"isExecuting"];
    dispatch_async(self.worker,^{
        dispatch_semaphore_signal(self.started);dispatch_semaphore_wait(self.gate,DISPATCH_TIME_FOREVER);record(self.rows,@"async-worker");
        [self willChangeValueForKey:@"isExecuting"];[self willChangeValueForKey:@"isFinished"];
        @synchronized(self){self->_working=NO;self->_done=YES;}
        [self didChangeValueForKey:@"isFinished"];[self didChangeValueForKey:@"isExecuting"];
    });
}
@end
static NSDictionary *named(NSDictionary *state,NSString *name) {NSDictionary *last=nil;for(NSDictionary *row in state[@"operations"])if([row[@"name"] isEqual:name])last=row;return last;}
static NSOperationQueue *queue(NSString *name) {NSOperationQueue *q=[NSOperationQueue new];q.name=name;q.maxConcurrentOperationCount=3;return q;}
static void configure(unsigned limit) {NSDictionary *r=DHFlowConfigureWithAPIs(YES,YES,limit,10000,nil,@[@"com.iosdecrypthub.flow.fixture",@"操作队列"],@[@"NSOperation",@"NSBlockOperation",@"dispatch_async"]);require([r[@"ok"] boolValue],r[@"error"]?:@"configure failed");}
NSDictionary *DHFlowOperationSelfTest(void) {
    static NSLock *lock;static dispatch_once_t once;dispatch_once(&once,^{lock=[NSLock new];});
    if(![lock tryLock])return @{@"pass":@NO,@"error":@"operation selftest is busy"};
    NSDictionary *initial=DHFlowState();
    if([initial[@"enabled"] boolValue] || [initial[@"pendingOrRunning"] unsignedIntValue]){[lock unlock];return @{@"pass":@NO,@"error":@"operation selftest requires inactive scheduler capture with no pending tasks"};}
    unsigned firstTask=[initial[@"retained"] unsignedIntValue];
    NSMutableDictionary *result=[@{@"pass":@NO} mutableCopy];NSMutableArray *passed=[NSMutableArray array],*rows=[NSMutableArray array];
    NSOperationQueue *q=nil;IDHOperationAsync *async=nil;
    DHFlowSetOwnedFixtureScope(YES);
    @try {
        configure(64);require([DHFlowOperationState()[@"ready"] boolValue],@"typed operation adapters unavailable");
        require([DHFlowOperationState()[@"blockInvokersReady"] boolValue],@"real Foundation block invokers not calibrated");
        q=queue(@"com.iosdecrypthub.flow.fixture");q.suspended=YES;
        IDHOperationSync *first=[IDHOperationSync new];first.name=@"idh-sync-dependency";
        first.body=^{record(rows,@"dependency");};
        NSBlockOperation *blocks=[NSBlockOperation blockOperationWithBlock:^{@synchronized(rows){require(rows.count>=1,@"dependency did not run first");}record(rows,@"block-one");}];blocks.name=@"idh-multiple-blocks";
        [blocks addExecutionBlock:^{record(rows,@"block-two");}];[blocks addDependency:first];
        require(blocks.dependencies.count==1 && blocks.dependencies.firstObject==first,@"operation/dependency identity changed");
        require(blocks.executionBlocks.count==2,@"execution block count changed");
        [q addOperations:@[blocks,first] waitUntilFinished:NO];q.suspended=NO;[q waitUntilAllOperationsAreFinished];
        require(first.finished && blocks.finished && rows.count==3,@"dependency/multiple blocks changed execution count");
        NSMutableSet *identities=[NSMutableSet set];for(NSDictionary *row in rows){require([row[@"taskId"] length]>0,@"operation callback lost its task identity");[identities addObject:row[@"taskId"]];}
        require(identities.count==3,@"parallel block callbacks shared one task token");
        result[@"dependencyAndWorkerObservations"]=[rows copy];
        NSDictionary *state=DHFlowOperationState(),*blockState=named(state,@"idh-multiple-blocks");
        require([blockState[@"workers"] count]==2 && [named(state,@"idh-sync-dependency")[@"executionMethod"] isEqual:@"main"],@"actual main/worker identities unavailable");
        [passed addObject:@"original-operation-dependencies-and-multiple-distinct-block-tasks"];

        configure(64);[rows removeAllObjects];IDHOperationOwnStart *ownStart=[IDHOperationOwnStart new];ownStart.name=@"idh-custom-synchronous-start";ownStart.body=^{record(rows,@"custom-start");};
        [q addOperation:ownStart];[q waitUntilAllOperationsAreFinished];
        require(!ownStart.asynchronous && !ownStart.concurrent && ownStart.mainCalls==0 && rows.count==1,@"custom synchronous start changed original execution path");
        require([rows[0][@"taskId"] length]>0,@"custom start with false asynchronous flag lost its actual callback context");
        NSDictionary *custom=named(DHFlowOperationState(),ownStart.name);
        require([custom[@"executionMethod"] isEqual:@"start"] && ![custom[@"isAsynchronous"] boolValue],@"callback selection incorrectly depended on asynchronous lifecycle flag");
        result[@"customStartObservations"]=[rows copy];[passed addObject:@"custom-start-override-is-observed-even-with-synchronous-lifecycle-flags"];

        configure(64);[rows removeAllObjects];async=[IDHOperationAsync new];async.name=@"idh-async-lifecycle";async.rows=rows;async.started=dispatch_semaphore_create(0);async.gate=dispatch_semaphore_create(0);async.worker=dispatch_queue_create("com.iosdecrypthub.flow.fixture",DISPATCH_QUEUE_SERIAL);
        [q addOperation:async];require(dispatch_semaphore_wait(async.started,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"asynchronous operation did not start");
        NSDictionary *pending=nil;for(unsigned i=0;i<100;i++){pending=named(DHFlowOperationState(),async.name);if([pending[@"startReturned"] boolValue])break;usleep(1000);}
        require([pending[@"startReturned"] boolValue] && ![pending[@"isFinished"] boolValue] && [pending[@"isExecuting"] boolValue] && [pending[@"executionMethod"] isEqual:@"start"],@"start return was confused with asynchronous completion");
        result[@"asyncPendingAfterStartReturn"]=pending;
        [async cancel];pending=named(DHFlowOperationState(),async.name);
        require([pending[@"isCancelled"] boolValue] && ![pending[@"isFinished"] boolValue],@"cancellation request falsely completed a running asynchronous operation");
        result[@"asyncPendingAfterCancel"]=pending;
        dispatch_semaphore_signal(async.gate);[q waitUntilAllOperationsAreFinished];
        require(async.finished && !async.executing && [named(DHFlowOperationState(),async.name)[@"isFinished"] boolValue],@"public asynchronous lifecycle changed");
        require(rows.count==2 && [rows[0][@"taskId"] length] && [rows[1][@"taskId"] length],@"async start/real GCD child lost context");
        result[@"asyncObservations"]=[rows copy];
        [passed addObject:@"asynchronous-start-return-is-separate-from-original-finished-state"];

        configure(64);__block unsigned cancelledCalls=0;NSBlockOperation *cancelled=[NSBlockOperation blockOperationWithBlock:^{cancelledCalls++;}];cancelled.name=@"idh-cancelled-before-start";[cancelled cancel];[q addOperation:cancelled];[q waitUntilAllOperationsAreFinished];
        state=DHFlowOperationState();NSDictionary *cancel=named(state,cancelled.name);
        require(cancelledCalls==0 && cancelled.cancelled && cancelled.finished && [cancel[@"isCancelled"] boolValue] && [cancel[@"isFinished"] boolValue],@"cancelled operation executed or changed lifecycle");
        for(NSDictionary *worker in cancel[@"workers"])require(![worker[@"observedEntries"] unsignedIntValue],@"cancelled block got a fabricated execution");
        require(![DHFlowState()[@"pendingOrRunning"] unsignedIntValue],@"finished cancelled operation leaked pending task tokens");
        [passed addObject:@"cancel-before-start-keeps-original-finish-without-fake-block-execution"];

        configure(64);[rows removeAllObjects];q.suspended=YES;
        NSBlockOperation *pendingBlock=[NSBlockOperation blockOperationWithBlock:^{record(rows,@"after-disable");}];pendingBlock.name=@"idh-disable-pending";[q addOperation:pendingBlock];
        DHFlowConfigure(NO,NO,1,1,nil,nil);q.suspended=NO;[q waitUntilAllOperationsAreFinished];
        require(rows.count==1 && [rows[0][@"taskId"] length] && pendingBlock.finished,@"disabling discarded an already submitted operation identity");
        [passed addObject:@"disable-preserves-pending-operation-and-original-callback"];

        configure(64);[rows removeAllObjects];q.suspended=YES;
        NSBlockOperation *monitored=[NSBlockOperation blockOperationWithBlock:^{record(rows,@"monitor-first");}];monitored.name=@"idh-app-owned-monitor";
        dispatch_queue_t monitorWorker=dispatch_queue_create("com.iosdecrypthub.flow.fixture",DISPATCH_QUEUE_SERIAL);
        dispatch_semaphore_t monitorHeld=dispatch_semaphore_create(0),monitorRelease=dispatch_semaphore_create(0);__block BOOL monitorTimedOut=NO;
        dispatch_async(monitorWorker,^{@synchronized(monitored){dispatch_semaphore_signal(monitorHeld);monitorTimedOut=dispatch_semaphore_wait(monitorRelease,dispatch_time(DISPATCH_TIME_NOW,3000000000))!=0;}});
        require(dispatch_semaphore_wait(monitorHeld,dispatch_time(DISPATCH_TIME_NOW,5000000000))==0,@"monitor fixture did not start");
        [monitored addExecutionBlock:^{record(rows,@"monitor-second");}];dispatch_semaphore_signal(monitorRelease);dispatch_sync(monitorWorker,^{});
        require(!monitorTimedOut,@"adapter acquired an App-owned operation monitor");
        [q addOperation:monitored];q.suspended=NO;[q waitUntilAllOperationsAreFinished];require(rows.count==2,@"private metadata lock changed original callback execution");
        [passed addObject:@"metadata-does-not-acquire-the-App-owned-operation-monitor"];

        configure(64);[rows removeAllObjects];q.suspended=YES;
        NSBlockOperation *late=[NSBlockOperation blockOperationWithBlock:^{record(rows,@"initial-block");}];late.name=@"idh-late-block";[q addOperation:late];
        [late addExecutionBlock:^{record(rows,@"late-block");}];require(late.executionBlocks.count==2,@"late block registration changed original block list");
        q.suspended=NO;[q waitUntilAllOperationsAreFinished];
        require(rows.count==2 && [rows[0][@"taskId"] length] && [rows[1][@"taskId"] length] && ![rows[0][@"taskId"] isEqual:rows[1][@"taskId"]],@"queued but not executing operation lost late block identity");
        result[@"lateBlockObservations"]=[rows copy];
        [passed addObject:@"adding-a-block-after-enqueue-keeps-original-execution-and-distinct-identity"];

        configure(64);[rows removeAllObjects];q.suspended=YES;
        NSBlockOperation *direct=[NSBlockOperation blockOperationWithBlock:^{record(rows,@"direct-and-queued");}];direct.name=@"idh-direct-block";[q addOperation:direct];
        dispatch_block_t exposed=direct.executionBlocks.firstObject;exposed();
        require(rows.count==1 && ![rows[0][@"taskId"] length],@"direct executionBlocks invocation stole a queued task identity");
        q.suspended=NO;[q waitUntilAllOperationsAreFinished];
        require(rows.count==2 && direct.finished,@"direct/queued execution changed original callback count");
        NSDictionary *directState=named(DHFlowOperationState(),direct.name);NSString *workerID=directState[@"workers"][0][@"taskId"];BOOL unresolved=NO;
        for(NSDictionary *task in DHFlowRead(firstTask,128,0)[@"tasks"])if([task[@"asyncTaskId"] isEqual:workerID])unresolved=[task[@"state"] isEqual:@"unresolved"] && [task[@"terminalReason"] isEqual:@"operation-block-outside-calibrated-execution"];
        require(unresolved,@"ambiguous direct callback was reported as a scheduled execution");
        result[@"directBlockObservations"]=[rows copy];
        [passed addObject:@"direct-block-invocation-forwards-without-stealing-pending-operation-edge"];

        configure(64);NSString *unicodeName=[@"操作队列" stringByPaddingToLength:90 withString:@"测试" startingAtIndex:0];NSOperationQueue *unicode=queue(unicodeName);
        IDHOperationSync *unicodeOperation=[IDHOperationSync new];unicodeOperation.name=@"idh-unicode-queue";[unicode addOperations:@[unicodeOperation] waitUntilFinished:YES];
        require(unicodeOperation.finished && [unicode.name isEqual:unicodeName] && [NSJSONSerialization dataWithJSONObject:DHFlowOperationState() options:0 error:NULL]!=nil,@"waitUntilFinished BOOL, Unicode diagnostics or original queue name changed");
        [passed addObject:@"long-Unicode-queue-name-preserves-original-and-readable-bounded-diagnostics"];

        configure(2);__block unsigned budgetCalls=0;
        for(unsigned i=0;i<12;i++)[q addOperationWithBlock:^{@synchronized(rows){budgetCalls++;}}];
        [q waitUntilAllOperationsAreFinished];require(budgetCalls==12,@"task budget prevented original queue callbacks");
        require([DHFlowState()[@"windowAccepted"] unsignedIntValue]==2,@"operation budget did not stay bounded");
        [passed addObject:@"budget-forwards-all-original-queue-blocks"];
        result[@"pass"]=@YES;result[@"passed"]=passed;result[@"state"]=DHFlowOperationState();result[@"flow"]=DHFlowState();result[@"taskEvidence"]=DHFlowRead(firstTask,128,0);result[@"restartRequired"]=@YES;
    }@catch(NSException *error){result[@"error"]=error.reason?:@"operation fixture failed";result[@"passed"]=passed;result[@"state"]=DHFlowOperationState();result[@"flow"]=DHFlowState();}
    @finally {if(async)dispatch_semaphore_signal(async.gate);q.suspended=NO;[q waitUntilAllOperationsAreFinished];DHFlowConfigure(NO,NO,1,1,nil,nil);DHFlowSetOwnedFixtureScope(NO);[lock unlock];}
    return result;
}
