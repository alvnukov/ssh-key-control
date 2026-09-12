#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

/// Creates a keychain access object that trusts no application, so every
/// read of an item created with it goes through the system's own prompt.
/// Returns NULL and sets *status on failure.
SecAccessRef _Nullable SSHKeyControlCreateRestrictedAccess(NSString *label, OSStatus *status)
    CF_RETURNS_RETAINED;

/// Brings the helper to the front so its dialog gets the keyboard.
void SSHKeyControlActivateApp(void);

NS_ASSUME_NONNULL_END
