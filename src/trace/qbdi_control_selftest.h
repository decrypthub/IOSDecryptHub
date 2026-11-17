#ifndef DH_QBDI_CONTROL_SELFTEST_H
#define DH_QBDI_CONTROL_SELFTEST_H
#import <Foundation/Foundation.h>
#ifdef __cplusplus
extern "C" {
#endif
NSDictionary *DHControlEnsureCalibrated(void);
NSDictionary *DHControlBackendSelfTest(void);
NSDictionary *DHControlBackendSelfTestWithBreakpoints(BOOL force);
NSDictionary *DHControlBackendState(void);
#ifdef __cplusplus
}
#endif
#endif
