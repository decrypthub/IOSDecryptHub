#include "idh_control_fixture_abi.h"
static volatile unsigned cleanups,calls;
struct NativeScope {~NativeScope(){cleanups++;}};
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlNativeCall(IDHControlFixtureRoot callback,uint64_t value) {
    NativeScope scope;return callback(value)+2;
}
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlNativeCatch(IDHControlFixtureRoot callback,uint64_t value) {
    try {NativeScope scope;return callback(value);}
    catch(const idh_control_fixture::Exact &e){return e.value+3;}
}
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlNativeOne(uint64_t value){calls++;return value+1;}
extern "C" __attribute__((noinline,optnone)) uint64_t IDHControlNativeTwo(uint64_t value){calls++;return value-1;}
extern "C" IDHControlFixturePair IDHControlNativePair(void){return {IDHControlNativeOne,IDHControlNativeTwo};}
extern "C" void IDHControlNativeReset(void){cleanups=calls=0;}
extern "C" unsigned IDHControlNativeCleanups(void){return cleanups;}
extern "C" unsigned IDHControlNativeCalls(void){return calls;}
