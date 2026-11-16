#ifndef DH_EVENT_H
#define DH_EVENT_H
#import <Foundation/Foundation.h>
#include <stdint.h>
@class DHLogEntry;
NSString *DHProcessGeneration(void);
NSString *DHCallID(uint64_t value);
uint64_t DHMonotonicNS(void);
void DHStampEvent(DHLogEntry *event);
NSDictionary *DHTargetIdentity(const void *address);
NSDictionary *DHExportPayload(NSDictionary *payload, NSUInteger maxBytes);
#endif
