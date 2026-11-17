#ifndef DH_FLOW_SOURCES_H
#define DH_FLOW_SOURCES_H
#import <Foundation/Foundation.h>
#include "fishhook.h"
const struct rebinding *DHFlowSourceBindings(size_t *count);
int DHFlowSourceOwnsImport(const char *name);
NSDictionary *DHFlowSourceState(void);
#endif
