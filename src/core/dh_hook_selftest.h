#import <Foundation/Foundation.h>
// 显式诊断：只执行自有 fixture；可选 getpid 导入测试会留下软停转发，重启目标才完全移除。
NSDictionary *DHHookSelfTest(BOOL includeCImport);
// 真实 Inline/QBDI 自检；只执行自有纯计算函数，Inline 软停后须重启清 patch。
NSDictionary *DHNativeBackendSelfTest(void);

NSDictionary *DHLiveBackendSelfTest(void);
