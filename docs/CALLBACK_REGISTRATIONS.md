# 1.28.44：处理器注册与实际回调

重复事件的处理器注册不等于提交一次队列工作。IDH 分别保留 `registrationId` 和每次实际进入回调时分配的 `asyncTaskId`，边类型为 `registered-handler-to-callback`。它不会为未来可能发生的事件预先创建 pending 任务，也不会把注册线程的 native 栈拼到执行线程上。

## 有界注册记录

每进程最多 128 个注册槽位，本代不复用；每窗口新增注册还受本窗口预算限制。记录实际注册 caller/callback、同步 call/异步 task 来源、线程、单调时间、最初队列和最多 32 帧注册栈。读取时才补符号/镜像身份。关闭、过期或重新开启另一窗口后，旧处理器继续执行，旧注册不自动扩大捕获窗口或补造历史父边。

每次捕获到的 delivery 仍受全局 1024 条任务、每窗口 256 条、64 个 pending/running、深度 8 的限制。`submittedNs` 在这种边上表示注册时间，`deliveryObservedNs` 表示本次回调入口；任务事件使用 `phase:delivery`，区别于真实队列提交的 `phase:submit`。函数/网络事件可携带 `asyncRegistrationId`，同步 `parentCallId` 保持原义。

`get_async_registrations` 的 offset 为 0–128、limit 为 1–8，默认 4。它返回当前进程的实际注册、观察/捕获次数、原始/当前已知队列与退休原因。每页是读取时的快照；`active` 只描述该观测记录的生命周期，不能单独推断对象仍在运行、一定会再触发或业务已经完成。

## dispatch source

适配公开 create、event/cancel/registration 三类 block 与 `_f` setter、cancel 和 set_target_queue，共九项导入，与原十一项 GCD 导入统一预检所有权并注册转发。

- 在显式窗口内观察到创建参数的 source，最多建立 64 个生命周期创建绑定；原队列来自真实 create/set_target_queue 参数。没有观察到创建的 source 不猜目标队列，继续原样转发并计数。
- 普通已识别 block 由原 source 调度。特殊 dispatch-block 和未知 block 保留原外层对象及 metadata，未支持的事件边明确无关联。cancel/registration 回调分别记录，不冒充事件回调。
- `_f` 每个注册使用独立、固定类型且不复用的转发入口，原 function 获得 libdispatch 实际传入的同一 context。不会替换 source context，也不读取私有 source 布局。自检用完全相同的 setter/context 变更序列比较未捕获与捕获结果，而不是猜某个系统版本如何取 context。
- 重复事件共用注册身份，每次进入拥有独立任务；替换、NULL 移除和处理器/对象释放分别退休观测记录。已在途的原 callback 仍执行。调用 cancel 只是提出请求，实际 cancel 回调、原事件结束和处理器释放分别发生，不能预先报告全部完成。
- set_target_queue 保留原调用，记录公开参数的变化；最初注册队列与当前已知目标分别提供。元数据不强持有 source，避免 source→handler→source 的观测环。

这些是公开导入及已选择对象的覆盖范围。dlsym 直调、框架内部入口、窗口前创建或未识别 handler 不保证产生边；注册表为空不能解释为 App 没有异步调度。

## 定向选择根入口

可选 `root_api_include` 与 `root_queue_include` 都是最多 8 个非空、无 NUL、127 UTF8 字节内的子串，忽略大小写，二者对根同时生效。它们只选择没有 async parent 的根，已选任务的后代可以换 API/队列；queue_exclude 仍优先生效。`rootAPIMisses` 单独计数，不消耗任务记录。

```json
{"process_generation":"<current-generation>","enabled":true,"capture_roots":true,"root_api_include":["dispatch_source"],"max_tasks":128,"max_ms":30000}
```

这使窗口可以等待 source 注册，而不是立即被普通 GCD 根耗尽。它不会恢复窗口前的历史注册；未命中仍应检查真实 native 栈与其它调度入口。

## 验证

`make test-flow-runtime` 与 `run_flow_selftest` 现为 30 组，新增 source block/function 的注册、重复事件、取消、未捕获 context 对照、替换/NULL 移除、特殊 block 放行、队列变更、未知旧 source、预算/关闭及根 API 筛选与 GCD 后代传播。两台运行后的只读接口回归：

```text
python tests/source_flow_mcp_test.py --endpoint http://<authorized-device>:8088
```

源码、整包与实际 App 的验证边界见 [PROGRESS.md](PROGRESS.md)。RunLoop/NSTimer、NSOperation、Swift Task、私有调度和 QBDI 异常透明执行仍是独立后续项。
