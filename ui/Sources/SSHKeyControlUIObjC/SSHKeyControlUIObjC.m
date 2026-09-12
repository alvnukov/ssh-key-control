#import "SSHKeyControlUIObjC.h"
#import <AppKit/AppKit.h>

// SecAccessCreate is deprecated without a replacement for file-based
// keychains, and activateIgnoringOtherApps: is the only activation that
// reliably takes focus from a terminal. Both are used on purpose.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

SecAccessRef SSHKeyControlCreateRestrictedAccess(NSString *label, OSStatus *status) {
    SecAccessRef access = NULL;
    CFArrayRef nobody = CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
    OSStatus rc = SecAccessCreate((__bridge CFStringRef)label, nobody, &access);
    CFRelease(nobody);
    if (status != NULL) {
        *status = rc;
    }
    if (rc != errSecSuccess) {
        return NULL;
    }
    return access;
}

void SSHKeyControlActivateApp(void) {
    [NSApp activateIgnoringOtherApps:YES];
}

#pragma clang diagnostic pop
