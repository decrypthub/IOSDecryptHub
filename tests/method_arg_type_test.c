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
    assert(dh_method_arg_size("B") == 1);
    assert(dh_method_arg_size("s") == 2);
    assert(dh_method_arg_size("i") == 4);
    assert(dh_method_arg_size("@") == 8);
    assert(dh_method_arg_size("r^v") == 8);
    assert(dh_method_arg_size("d") == 0);
    unsigned end = 0;
    assert(dh_method_stack_offset(end, 1) == 0); end = 1;
    assert(dh_method_stack_offset(end, 1) == 1); end = 2;
    assert(dh_method_stack_offset(end, 8) == 8); end = 16;
    assert(dh_method_stack_offset(end, 8) == 16);
    printf("PASS: %u Objective-C argument type cases\n", count);
    puts("PASS: 10 Darwin argument size and packed-stack alignment cases");
    return 0;
}
