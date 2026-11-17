#import <Foundation/Foundation.h>
#import "dh_unwind.h"
#include <stdio.h>
int main(void) {@autoreleasepool {
    if(!dh_unwind_recipe_available()){puts("SKIP: native arm64 recipe unwinder APIs unavailable");return 0;}
    NSDictionary *result=DHUnwindRecipeSelfTest();
    NSData *json=[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];fwrite(json.bytes,1,json.length,stdout);putchar('\n');
    if(![result[@"pass"] boolValue])return 1;
    NSDictionary *old=DHDecodeRawStack(@"IDH_NATIVE_STACK_V2 1 1 0 0 6 0 1234 5678 7890 5000 9000 1200 1300\n1234 5678\n");
    if(![old[@"complete"] boolValue] || [old[@"recoveredSteps"] unsignedIntValue])return 2;
    NSDictionary *legacy=DHDecodeRawStack(@"IDH_NATIVE_STACK_V1 1 1 0 0\n1 2\n");if(![legacy[@"complete"] boolValue])return 3;
    NSDictionary *bad=DHDecodeRawStack(@"IDH_NATIVE_STACK_V3 1 1 0 0 6 0 1234 5678 7890 5000 9000 1200 1300 0\n1234 5678 33\n");
    if([bad[@"complete"] boolValue] || ![bad[@"truncated"] boolValue])return 4;
    NSDictionary *oldGeneration=DHResolveStack(result[@"repaired"],NO);
    if(![oldGeneration[@"recipeMetadata"] containsString:@"unavailable-for-old-generation"])return 5;
    puts("PASS: real missing-CFI repair, full GPR/DWARF caller and legacy/V3 records");return 0;
}}
