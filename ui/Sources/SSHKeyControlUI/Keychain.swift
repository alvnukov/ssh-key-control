import SSHKeyControlUIObjC
import Foundation
import Security

/// Generic passwords in the login keychain, service "ssh-key-control". Items are
/// created with an access list that trusts nobody, so macOS asks the user
/// before every read; the helper never gets a secret silently.
public struct Keychain: SecretStore {
    public static let service = "ssh-key-control"

    public init() {}

    public func get(account: String) throws -> String {
        var query = base(account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { throw Self.failure(status, "reading") }
        guard let data = item as? Data, let secret = String(data: data, encoding: .utf8) else {
            throw Failure.other("keychain item for \(account) is not text")
        }
        return secret
    }

    public func set(account: String, secret: String) throws {
        // Replace rather than update: an update would keep the old access list.
        let deleted = SecItemDelete(base(account) as CFDictionary)
        guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
            throw Self.failure(deleted, "replacing")
        }
        var status: OSStatus = errSecSuccess
        guard let access = SSHKeyControlCreateRestrictedAccess("\(Self.service): \(account)", &status) else {
            throw Self.failure(status, "creating the access list for")
        }
        var attrs = base(account)
        attrs[kSecAttrLabel] = "\(Self.service): \(account)"
        attrs[kSecValueData] = Data(secret.utf8)
        attrs[kSecAttrAccess] = access
        let added = SecItemAdd(attrs as CFDictionary, nil)
        guard added == errSecSuccess else { throw Self.failure(added, "storing") }
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(base(account) as CFDictionary)
        guard status == errSecSuccess else { throw Self.failure(status, "deleting") }
    }

    private func base(_ account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: account,
            // The file-based login keychain: the only one with per-item access lists.
            kSecUseDataProtectionKeychain: false,
        ]
    }

    static func failure(_ status: OSStatus, _ verb: String) -> Failure {
        switch status {
        case errSecItemNotFound:
            return .notFound
        case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed, errSecInteractionRequired:
            return .denied
        default:
            let text = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return .other("keychain: \(verb) the item failed: \(text)")
        }
    }
}
