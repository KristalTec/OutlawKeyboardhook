#ifndef OUTLAW_SUBSTRATE_H
#define OUTLAW_SUBSTRATE_H

#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

void MSHookFunction(void *symbol, void *replacement, void **result);
void MSHookMessageEx(Class _class, SEL message, IMP replacement, IMP *result);
void *MSFindSymbol(void *image, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* OUTLAW_SUBSTRATE_H */
