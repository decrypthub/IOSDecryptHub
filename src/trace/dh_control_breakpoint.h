#ifndef DH_CONTROL_BREAKPOINT_H
#define DH_CONTROL_BREAKPOINT_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int dh_control_breakpoint_prepare(char *error,size_t size);
int dh_control_breakpoint_force_for_selftest(int enabled);
int dh_control_breakpoint_forced(void);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHControlBreakpointState(void);
#endif
#ifdef __cplusplus
}
#endif
#endif
