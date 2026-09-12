import Foundation

/// What the dialogs must do. AppKitDialogs is the real one; tests use fakes.
@MainActor
public protocol Dialogs {
    /// Asks for a secret. `remember` is the checkbox label, nil for no checkbox.
    func secret(title: String, message: String, remember: String?) throws -> (secret: String, remember: Bool)
    /// Asks for visible text.
    func text(title: String, message: String, placeholder: String) throws -> String
    /// Asks a yes/no question; true means allowed.
    func confirm(title: String, message: String, allow: String, deny: String) throws -> Bool
    func confirmScoped(title: String, message: String, allow: String, deny: String, destination: String) throws -> Confirmation
    /// Shows a panel and returns at once; the panel lives until the process ends.
    func notify(title: String, message: String) throws
}

public extension Dialogs {
    /// Older implementations can only grant this request once.
    func confirmScoped(title: String, message: String, allow: String, deny: String, destination: String) throws -> Confirmation {
        Confirmation(allowed: try confirm(title: title, message: message, allow: allow, deny: deny))
    }
}
/// Where secrets are kept between runs. Keychain is the real one.
public protocol SecretStore {
    func get(account: String) throws -> String
    func set(account: String, secret: String) throws
    func delete(account: String) throws
}

/// Turns requests into responses.
@MainActor
public struct Dispatcher {
    let dialogs: any Dialogs
    let store: any SecretStore

    public init(dialogs: any Dialogs, store: any SecretStore) {
        self.dialogs = dialogs
        self.store = store
    }

    public func handle(_ req: Request) -> Response {
        do {
            return try dispatch(req)
        } catch {
            return .failure(error)
        }
    }

    private func dispatch(_ req: Request) throws -> Response {
        switch req.op {
        case .secret:
            let (secret, remember) = try dialogs.secret(
                title: req.title ?? "", message: req.message ?? "", remember: req.remember?.label)
            return .success(answer: secret, remember: req.remember == nil ? nil : remember)
        case .text:
            let answer = try dialogs.text(
                title: req.title ?? "", message: req.message ?? "", placeholder: req.placeholder ?? "")
            return .success(answer: answer)
        case .confirm:
            if let destination = req.destination, !destination.isEmpty {
                let choice = try dialogs.confirmScoped(
                    title: req.title ?? "", message: req.message ?? "",
                    allow: req.allow ?? "Allow", deny: req.deny ?? "Deny", destination: destination)
                return .confirmation(choice)
            }
            let allowed = try dialogs.confirm(
                title: req.title ?? "", message: req.message ?? "",
                allow: req.allow ?? "Allow", deny: req.deny ?? "Deny")
            return .success(answer: allowed ? "yes" : "no")
        case .notify:
            try dialogs.notify(title: req.title ?? "", message: req.message ?? "")
            return .success()
        case .keychainGet:
            return .success(answer: try store.get(account: try account(req)))
        case .keychainSet:
            guard let secret = req.secret else { throw Failure.other("keychain.set needs a secret") }
            try store.set(account: try account(req), secret: secret)
            return .success()
        case .keychainDelete:
            try store.delete(account: try account(req))
            return .success()
        }
    }

    private func account(_ req: Request) throws -> String {
        guard let account = req.account, !account.isEmpty else {
            throw Failure.other("\(req.op.rawValue) needs an account")
        }
        return account
    }
}
