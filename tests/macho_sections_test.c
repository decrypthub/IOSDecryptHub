#include <assert.h>
#include <stdio.h>
#include "dh_macho_sections.h"

struct Segment { struct segment_command_64 sg; struct section_64 sec; };
struct Fixture { struct mach_header_64 mh; struct Segment segments[3]; };

static struct Fixture fixture(void) {
    struct Fixture f = {0};
    f.mh.magic = MH_MAGIC_64;
    f.mh.ncmds = 3;
    f.mh.sizeofcmds = sizeof(f.segments);
    const char *names[] = {"__TEXT", "__CUSTOM_EXEC", "__CUSTOM_RO"};
    const char *sections[] = {"__const", "__text", "__cstring"};
    for (int i = 0; i < 3; i++) {
        struct Segment *s = &f.segments[i];
        s->sg.cmd = LC_SEGMENT_64;
        s->sg.cmdsize = sizeof(*s);
        strcpy(s->sg.segname, names[i]);
        s->sg.vmaddr = 0x100000000ULL + (uint64_t)i * 0x8000;
        s->sg.vmsize = 0x1000;
        s->sg.initprot = i == 2 ? VM_PROT_READ : VM_PROT_READ | VM_PROT_EXECUTE;
        s->sg.nsects = 1;
        strcpy(s->sec.segname, names[i]);
        strcpy(s->sec.sectname, sections[i]);
        s->sec.addr = s->sg.vmaddr + 0x100;
        s->sec.size = 0x200;
    }
    return f;
}

int main(void) {
    struct Fixture f = fixture();
    assert(dh_macho_find_section(&f.mh, "__TEXT", "__text") == &f.segments[1].sec);
    assert(dh_macho_find_section(&f.mh, "__TEXT", "__cstring") == &f.segments[2].sec);
    assert(!dh_macho_find_section(&f.mh, "__DATA", "__got"));
    assert(dh_macho_contains_exec(&f.mh, 0x4000, 0x10000c100ULL));
    assert(!dh_macho_contains_exec(&f.mh, 0x4000, 0x100008000ULL));
    assert(!dh_macho_contains_exec(&f.mh, 0x4000, 0x100014100ULL));
    strcpy(f.segments[0].sec.sectname, "__text");
    assert(dh_macho_find_section(&f.mh, "__TEXT", "__text") == &f.segments[0].sec);
    f = fixture(); f.segments[1].sg.initprot = VM_PROT_READ;
    assert(!dh_macho_find_section(&f.mh, "__TEXT", "__text"));
    f = fixture(); f.segments[1].sec.size = 0x1001;
    assert(!dh_macho_find_section(&f.mh, "__TEXT", "__text"));
    f = fixture(); f.segments[0].sg.cmdsize = 1;
    assert(!dh_macho_find_section(&f.mh, "__TEXT", "__text"));
    puts("PASS: 10 Mach-O custom-section and executable-range cases");
    return 0;
}
