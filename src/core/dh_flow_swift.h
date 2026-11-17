#ifndef DH_FLOW_SWIFT_H
#define DH_FLOW_SWIFT_H
#include <stdint.h>
uint64_t DHSwiftCurrentToken(void);
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHSwiftState(void);
NSDictionary *DHSwiftRead(unsigned offset,unsigned limit);
NSDictionary *DHSwiftEvents(uint64_t after,unsigned limit,uint64_t task);
NSDictionary *DHSwiftFieldsCurrent(void);
NSDictionary *DHSwiftFieldsForToken(uint64_t token);
NSDictionary *DHSwiftConfigure(BOOL enabled,unsigned budget,unsigned milliseconds);
NSDictionary *DHSwiftSelfTest(void);
#endif
#endif
