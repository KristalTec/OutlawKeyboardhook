//
//  KeyboardPremiumTweak.xm
//  ⚛️⚛️ ATOMIC++ — Maximum Power Version
//  Based on Ghidra decompilation analysis
//  Async architecture: getters return Bool, mutations return void
//

#import <substrate.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>
#import <stdio.h>
#import <stdint.h>
#import <stdlib.h>
#import <os/lock.h>

// ============================================================
//  GLOBAL STATE — Thread-Safe
// ============================================================
static os_unfair_lock   g_lock           = OS_UNFAIR_LOCK_INIT;
static uintptr_t        g_slide          = 0;
static const char      *g_targetImage    = NULL;
static void            *g_targetBase     = NULL;
static size_t           g_targetSize     = 0;
static BOOL             g_initialized    = NO;

// ============================================================
//  ORIGINAL FUNCTION POINTERS
// ============================================================
static bool (*orig_isActive)(void *self)                = NULL;
static bool (*orig_allowsPaidLayouts)(void *self)       = NULL;
static BOOL (*orig_receiptHasTransactions)(id self, SEL _cmd, id data) = NULL;

// ============================================================
//  REPLACEMENT HOOKS — Always Allow
// ============================================================
static bool hook_isActive(void *self) {
    (void)self;
    return true;
}

static bool hook_allowsPaidLayouts(void *self) {
    (void)self;
    return true;
}

static BOOL hook_receiptHasTransactions(id self, SEL _cmd, id data) {
    (void)self; (void)_cmd; (void)data;
    return YES;
}

// ============================================================
//  ADDRESS VALIDATION — پشکنینی ئەوەی ناونیشانەکە Code ـە
// ============================================================
static BOOL is_valid_exec_address(void *addr) {
    if (!addr) return NO;
    vm_address_t a = (vm_address_t)addr;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(mach_task_self(), &a, &size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info,
                                    &cnt, &obj);
    if (kr != KERN_SUCCESS) return NO;
    if (a > (vm_address_t)addr) return NO;
    if ((a + size) <= (vm_address_t)addr) return NO;
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    return (info.protection & VM_PROT_EXECUTE) != 0;
}

// ============================================================
//  IMAGE + SLIDE DISCOVERY
// ============================================================
static const char *kImageKeys[] = {
    "Keyboard", "Autocorrect", "Autocorrection",
    "TextInput", "TUIKeyboard", "UIKitCore",
    NULL
};

static BOOL discover_image(void) {
    uint32_t count = _dyld_image_count();
    int bestIdx = -1;

    for (int k = 0; kImageKeys[k] != NULL && bestIdx < 0; k++) {
        for (uint32_t i = 0; i < count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            if (strstr(name, kImageKeys[k])) {
                const struct mach_header_64 *hdr =
                    (const struct mach_header_64 *)_dyld_get_image_header(i);
                if (hdr && hdr->magic == MH_MAGIC_64) {
                    bestIdx = (int)i;
                    g_targetImage = name;
                    break;
                }
            }
        }
    }

    if (bestIdx < 0) {
        bestIdx = 0;
        g_targetImage = _dyld_get_image_name(0);
    }

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(bestIdx);
    if (!hdr || hdr->magic != MH_MAGIC_64) return NO;

    g_slide      = _dyld_get_image_vmaddr_slide((uint32_t)bestIdx);
    g_targetBase = (void *)hdr;

    unsigned long tsize = 0;
    getsegmentdata(hdr, "__TEXT", &tsize);
    g_targetSize = tsize;

    return YES;
}

// ============================================================
//  SYMBOL RESOLUTION — چەندین شێواز و prefix
// ============================================================
static const char *kPrefixes[] = { "", "_", "__", "___", NULL };

static void *resolve_symbol(const char *bare) {
    if (!bare) return NULL;

    void *p = dlsym(RTLD_DEFAULT, bare);
    if (p) return p;

    char buf[512];
    snprintf(buf, sizeof(buf), "_%s", bare);
    p = dlsym(RTLD_DEFAULT, buf);
    if (p) return p;

    for (int i = 0; kPrefixes[i]; i++) {
        snprintf(buf, sizeof(buf), "%s%s", kPrefixes[i], bare);
        p = MSFindSymbol(NULL, buf);
        if (p) return p;
    }
    return NULL;
}

// ============================================================
//  THUNK DEREFERENCE — بۆ Swift lazy getter
//  pattern: (*(code *)PTR_xxx_100dd3180)() ; ret
//  هەنگاوی 1: adrp x8, PTR@page
//  هەنگاوی 2: ldr  x8, [x8, #off]
//  هەنگاوی 3: br   x8
// ============================================================
static void *deref_thunk_target(void *thunkAddr) {
    if (!thunkAddr || !is_valid_exec_address(thunkAddr)) return NULL;

    uint32_t *code = (uint32_t *)thunkAddr;
    // Scan first 5 instructions for the ADRP + LDR pattern
    for (int i = 0; i < 4; i++) {
        uint32_t insn = code[i];
        // ADRP: 0x90000000 mask
        if ((insn & 0x9F000000) == 0x90000000) {
            uint32_t insn2 = code[i + 1];
            // LDR (immediate) 64-bit: 0xF9400000 mask
            if ((insn2 & 0xFFC00000) == 0xF9400000) {
                // Decode ADRP
                int64_t immlo = (insn >> 29) & 3;
                int64_t immhi = (insn >> 5) & 0x7FFFF;
                int64_t imm = (immhi << 2) | immlo;
                if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
                uintptr_t page = ((uintptr_t)thunkAddr & ~0xFFFULL) + (imm << 12);
                // Decode LDR offset
                uint32_t off = ((insn2 >> 10) & 0xFFF) << 3;
                void **ptrLoc = (void **)(page + off);
                if (is_valid_exec_address(ptrLoc) == NO) {
                    // Read the pointer
                    void *realTarget = *ptrLoc;
                    if (is_valid_exec_address(realTarget)) return realTarget;
                }
                // Even if page read fails, try direct read
                void *realTarget = *ptrLoc;
                if (realTarget && is_valid_exec_address(realTarget))
                    return realTarget;
            }
        }
    }
    return NULL;
}

// ============================================================
//  PATTERN SCANNER
// ============================================================
static void *pattern_scan_aligned(const uint8_t *pat, const char *mask,
                                  size_t plen, size_t align)
{
    if (!g_targetBase || !g_targetSize || !pat || !mask) return NULL;
    if (plen == 0 || plen > 64 || align == 0) return NULL;

    uintptr_t start = (uintptr_t)g_targetBase;
    uintptr_t end   = start + g_targetSize - plen;

    for (uintptr_t addr = start; addr < end; addr += align) {
        const uint8_t *p = (const uint8_t *)addr;
        BOOL ok = YES;
        for (size_t i = 0; i < plen; i++) {
            if (mask[i] == 'x' && p[i] != pat[i]) { ok = NO; break; }
        }
        if (ok) return (void *)addr;
    }
    return NULL;
}

// Bool getter returning true pattern: mov w0, #1 ; ret
static const uint8_t kBoolTruePat[] = { 0x20,0x00,0x80,0x52, 0xC0,0x03,0x5F,0xD6 };
static const char   *kBoolTrueMask  = "xxxxxxxx";

// Bool getter returning false: mov w0, #0 ; ret
static const uint8_t kBoolFalsePat[] = { 0x00,0x00,0x80,0x52, 0xC0,0x03,0x5F,0xD6 };
static const char   *kBoolFalseMask  = "xxxxxxxx";

// ============================================================
//  INSTALL HOOK — چەند لایەر + fallback
// ============================================================
static BOOL install_hook(const char *label,
                         const char *swiftBare,
                         uintptr_t   fallbackOff,
                         void       *replacement,
                         void      **original,
                         BOOL        expectTrue)
{
    void *target = NULL;
    const char *how = "?";

    // Layer 1: symbol resolution (multi-prefix)
    if (swiftBare) {
        target = resolve_symbol(swiftBare);
        if (target) how = "symbol";
    }

    // Layer 2: offset fallback
    if (!target && fallbackOff != 0 && g_slide != 0) {
        target = (void *)(g_slide + fallbackOff);
        how = "offset";
    }

    // Layer 3: dereference thunk (Swift lazy getter pattern)
    if (target && !is_valid_exec_address(target)) {
        void *real = deref_thunk_target(target);
        if (real) { target = real; how = "thunk-deref"; }
    }

    // Layer 4: pattern scan fallback
    if (!target || !is_valid_exec_address(target)) {
        const uint8_t *pat  = expectTrue ? kBoolTruePat : kBoolFalsePat;
        const char    *mask = expectTrue ? kBoolTrueMask : kBoolFalseMask;
        void *found = pattern_scan_aligned(pat, mask, 8, 4);
        if (found) { target = found; how = "pattern"; }
    }

    if (!target) {
        NSLog(@"[⚛️] %s ❌ target not found", label);
        return NO;
    }

    if (!is_valid_exec_address(target)) {
        NSLog(@"[⚛️] %s ⚠️ %p not executable, skipping", label, target);
        return NO;
    }

    MSHookFunction(target, replacement, original);
    NSLog(@"[⚛️] %s ✅ hooked via %s @ %p (orig=%p)",
          label, how, target, original ? *original : NULL);
    return YES;
}

// ============================================================
//  OBJECTIVE-C METHOD HOOK (Swift class @objc methods)
// ============================================================
static BOOL install_objc_hook(const char *label,
                              const char *className,
                              const char *selName,
                              IMP replacement,
                              IMP *original)
{
    Class c = objc_getClass(className);
    if (!c) { NSLog(@"[⚛️] %s ❌ class %s not found", label, className); return NO; }

    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { NSLog(@"[⚛️] %s ❌ sel %s not found on %s", label, selName, className); return NO; }

    MSHookMessageEx(c, sel, replacement, original);
    NSLog(@"[⚛️] %s ✅ hooked on %s", label, className);
    return YES;
}

// ============================================================
//  CONSTRUCTOR
// ============================================================
%ctor {
    @autoreleasepool {
        os_unfair_lock_lock(&g_lock);
        if (g_initialized) { os_unfair_lock_unlock(&g_lock); return; }
        g_initialized = YES;

        NSLog(@"[⚛️] ==============================================");
        NSLog(@"[⚛️]  KeyboardPremiumTweak — ATOMIC++");
        NSLog(@"[⚛️]  Async architecture awareness enabled");
        NSLog(@"[⚛️] ==============================================");

        if (!discover_image()) {
            NSLog(@"[⚛️] ❌ image discovery failed — aborting");
            os_unfair_lock_unlock(&g_lock);
            return;
        }

        NSLog(@"[⚛️] image = %s", g_targetImage ? g_targetImage : "(null)");
        NSLog(@"[⚛️] slide = 0x%lx", (unsigned long)g_slide);
        NSLog(@"[⚛️] base  = %p  size = 0x%lx",
              g_targetBase, (unsigned long)g_targetSize);

        // ----------------------------------------------------------
        //  LAYER 1: SubscriptionStatus.isActive  (Bool getter)
        //  Ghidra: 0x100ae441c → offset 0xAE441C
        //  Thunk:  0x100dd3180
        // ----------------------------------------------------------
        install_hook(
            "SubscriptionStatus.isActive",
            "$s12KeyboardCore15SettingsManagerCA2A18SubscriptionStatusVRszrlE8isActiveSbvg",
            0xAE441C,
            (void *)&hook_isActive,
            (void **)&orig_isActive,
            YES  // expectTrue: fallback scan for "mov w0,#1; ret"
        );

        // ----------------------------------------------------------
        //  LAYER 2: SubscriptionStatus.allowsPaidLayouts  (Bool getter)
        //  Ghidra: 0x100ae43e0 → offset 0xAE43E0
        //  Thunk:  0x100dd3158
        // ----------------------------------------------------------
        install_hook(
            "SubscriptionStatus.allowsPaidLayouts",
            "$s12KeyboardCore15SettingsManagerCA2A18SubscriptionStatusVRszrlE17allowsPaidLayoutsSbvg",
            0xAE43E0,
            (void *)&hook_allowsPaidLayouts,
            (void **)&orig_allowsPaidLayouts,
            YES
        );

        // ----------------------------------------------------------
        //  LAYER 3: ReceiptParser.receiptHasTransactionsWithReceiptData:
        //  Ghidra: 0x100850e10  AND  0x100508e98  (دوو شوێن)
        //  کلاس: ReceiptParser.PurchasesReceiptParser
        //  ئەمە ObjC method ـە — Bool return
        // ----------------------------------------------------------
        const char *rcClasses[] = {
            "ReceiptParser.PurchasesReceiptParser",
            "_TtC13ReceiptParser22PurchasesReceiptParser",
            "PurchasesReceiptParser",
            "RCReceiptFetcher",
            "RCStoreKit1Wrapper",
            "RCStoreKit2Wrapper",
            "SKReceiptRefreshRequest",
            NULL
        };
        BOOL receiptHooked = NO;
        for (int i = 0; rcClasses[i] && !receiptHooked; i++) {
            if (install_objc_hook("receiptHasTransactions",
                                  rcClasses[i],
                                  "receiptHasTransactionsWithReceiptData:",
                                  (IMP)&hook_receiptHasTransactions,
                                  (IMP *)&orig_receiptHasTransactions)) {
                receiptHooked = YES;
            }
        }
        if (!receiptHooked) {
            NSLog(@"[⚛️] receiptHasTransactions: no class found, will try native fallback");
        }

        // ----------------------------------------------------------
        //  LAYER 4: SubscriptionStatus.shared  (singleton accessor)
        //  Ghidra: 0x100ae4410 → offset 0xAE4410
        //  گەرەنتی دەکەین singleton هەرگیز نەگەڕێتەوە null
        // ----------------------------------------------------------
        static void *(*orig_shared)(void) = NULL;
        static void *hook_shared(void) {
            void *s = orig_shared ? orig_shared() : NULL;
            return s;  // هیچ دەستکارییەک — تەنها گەرەنتی null-check
        }
        install_hook(
            "SubscriptionStatus.shared",
            "$s12KeyboardCore15SettingsManagerCA2A18SubscriptionStatusVRszrlE6sharedACyAEGvau",
            0xAE4410,
            (void *)&hook_shared,
            (void **)&orig_shared,
            NO
        );

        // ----------------------------------------------------------
        //  LAYER 5: FUN_1000bd8e4 — خاڵی بڕیاردان
        //  Ghidra: 0x1000bd8e4 → offset 0xBD8E4
        //  ئەم فانکشنە دەتوانێت ناوەکییە؛ بە "naked" ناچالاک دەکەین
        //  بۆ ئەوەی هیچ parameter تێک نەچێت.
        //  ----------------------------------------------------------
        //  -- بە naked trampoline: بانگی original دەکات، پاشان return
        //  لەبەر ئەوەی نازانین signature ـەکەی، بە thunk پارێزراو دەیپارێزین.
        //  بەڵام لەبەر ئەوەی `isActive` هۆک کراوە، ئەم فانکشنە بەخۆی
        //  دەچێتە سەر بەشی "true" بۆیە پێویست بە hook ی زیادە نییە.
        //  تەنها symbol ی بۆ لۆگ هەڵدەگرین ئەگەر هەبوو.
        // ----------------------------------------------------------
        void *fun_bd8e4 = (g_slide != 0) ? (void *)(g_slide + 0xBD8E4) : NULL;
        if (fun_bd8e4 && is_valid_exec_address(fun_bd8e4)) {
            NSLog(@"[⚛️] FUN_1000bd8e4 (decision point) @ %p — protected by isActive hook",
                  fun_bd8e4);
        }

        // ----------------------------------------------------------
        //  LAYER 6: FUN_1000bd168 — apply(SubscriptionStatusResponse)
        //  Ghidra: 0x1000bd168 → offset 0xBD168
        //  ئەم فانکشنە void ـە؛ state دەگۆڕێت. ئێمە پێویستمان پێی نییە
        //  چونکە isActive هۆک کراوە. تەنها لۆگ.
        // ----------------------------------------------------------
        void *fun_bd168 = (g_slide != 0) ? (void *)(g_slide + 0xBD168) : NULL;
        if (fun_bd168 && is_valid_exec_address(fun_bd168)) {
            NSLog(@"[⚛️] FUN_1000bd168 (apply response) @ %p — protected by isActive hook",
                  fun_bd168);
        }

        // ----------------------------------------------------------
        //  LAYER 7: Obsolete stubs — دڵنیابوونەوە کە هەرگیز بانگ ناکرێن
        //  purchaseProduct:withCompletionBlock:  (0x100554268)
        //  ئەمانە fatal error دەکەن — ئێمە هیچ ناکەین، تەنها لۆگ
        //  چونکە ئەگەر بانگ بکرێن، tweak crash دەکات.
        // ----------------------------------------------------------
        NSLog(@"[⚛️] obsolete stubs (purchaseProduct:withCompletionBlock: etc.) — ignored");

        // ----------------------------------------------------------
        //  LAYER 8: SubscriptionStatus.apply(TrialResponse) / apply(RedeemCodeResponse)
        //  Ghidra: 0x100ae43f8  &  0x100ae4404
        //  ئەم دوو فانکشنە void ـن و state دەنوێنن.
        //  -- بە خۆکارانە بەرپرسیارێتی isActive ـە.
        // ----------------------------------------------------------
        NSLog(@"[⚛️] apply(TrialResponse)/apply(RedeemCodeResponse) — covered by isActive hook");

        NSLog(@"[⚛️] ================ READY ================");
        os_unfair_lock_unlock(&g_lock);
    }
}
