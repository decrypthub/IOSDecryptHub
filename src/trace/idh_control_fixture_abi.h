#ifndef IDH_CONTROL_FIXTURE_ABI_H
#define IDH_CONTROL_FIXTURE_ABI_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
namespace idh_control_fixture {struct Exact {uint64_t value;const void *identity;};}
extern "C" {
#endif
enum {IDH_CF_COMPOSITE=0,IDH_CF_CPP_OUT,IDH_CF_OBJC_OUT,IDH_CF_JUMP_OUT,IDH_CF_SIGJUMP_OUT,IDH_CF_NORMAL,IDH_CF_MODES};
enum {IDH_CF_CALLS=0,IDH_CF_CPP_CLEANUPS,IDH_CF_FINALLY,IDH_CF_CATCHES,IDH_CF_AFTER,IDH_CF_COMPOSITES,IDH_CF_NATIVE_CLEANUPS,IDH_CF_NATIVE_CALLS,IDH_CF_THREAD,IDH_CF_STATS};
typedef uint64_t (*IDHControlFixtureRoot)(uint64_t);
typedef struct {IDHControlFixtureRoot one,two;} IDHControlFixturePair;
unsigned IDHControlFixtureVersion(void);
void IDHControlFixtureReset(void);
IDHControlFixtureRoot IDHControlFixtureGetRoot(unsigned mode);
uint64_t IDHControlFixtureInvoke(unsigned mode,uint64_t value);
int IDHControlFixtureStats(uint64_t *out,size_t count);
uint64_t IDHControlFixtureAfterPC(void);

uint64_t IDHControlNativeCall(IDHControlFixtureRoot callback,uint64_t value);
uint64_t IDHControlNativeCatch(IDHControlFixtureRoot callback,uint64_t value);
uint64_t IDHControlNativeOne(uint64_t value);
uint64_t IDHControlNativeTwo(uint64_t value);
IDHControlFixturePair IDHControlNativePair(void);
void IDHControlNativeReset(void);
unsigned IDHControlNativeCleanups(void);
unsigned IDHControlNativeCalls(void);
#ifdef __cplusplus
}
#endif
#endif
