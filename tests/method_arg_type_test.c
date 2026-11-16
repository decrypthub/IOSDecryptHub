#include <assert.h>
#include <stdio.h>
#include "dh_method_arg_type.h"

int main(void) {
    struct { const char *type; int expected; } cases[] = {
        {"@", 2}, {"@\"NSString\"", 2}, {"@?", 2}, {"#", 2},
        {"r@", 2}, {"n^@", 1}, {"^v", 1}, {"*", 1}, {":", 1},
        {"B", 1}, {"q", 1}, {"Q", 1}, {"rI", 1},
        {"f", 0}, {"d", 0}, {"D", 0}, {"{Pair=qq}", 0},
        {"[4i]", 0}, {"(Value=qd)", 0}, {"!16,16f", 0},
        {"jD", 0}, {"", 0}, {"r", 0}, {NULL, 0},
    };
    unsigned count = sizeof(cases) / sizeof(cases[0]);
    for (unsigned i = 0; i < count; i++)
        assert(dh_method_arg_type(cases[i].type) == cases[i].expected);
    printf("PASS: %u Objective-C argument type cases\n", count);
    return 0;
}
