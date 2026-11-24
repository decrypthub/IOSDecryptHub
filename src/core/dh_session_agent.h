#if DH_DEVICE_SESSIONS
#import <Foundation/Foundation.h>
@class DHLogEntry;

void dh_session_agent_prepare(void);
BOOL dh_session_agent_start(void);
void dh_session_record(DHLogEntry *entry, BOOL update);
#endif
