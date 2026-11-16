#import <Foundation/Foundation.h>
// 显式诊断：只执行自有 fixture；可选 getpid 导入测试会留下软停转发，重启目标才完全移除。
NSDictionary *DHHookSelfTest(BOOL includeCImport);
