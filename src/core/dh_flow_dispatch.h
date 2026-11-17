#ifndef DH_FLOW_DISPATCH_H
#define DH_FLOW_DISPATCH_H
#ifdef __OBJC__
#import <Foundation/Foundation.h>
NSDictionary *DHDispatchEntryState(void);
NSDictionary *DHDispatchEntryConfigure(BOOL enabled);
NSDictionary *DHDispatchEntrySelfTest(void);
#endif
#endif
