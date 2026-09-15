import Foundation
import XCTest

@testable import SSHKeyControlUI

@MainActor
final class FakeDialogs: Dialogs {
    var secretAnswer = (secret: "s3cret", remember: true)
    var textAnswer = "yes"
    var confirmAnswer = true
    var error: Failure?
    var calls: [String] = []

    func secret(title: String, message: String, remember: String?) throws -> (secret: String, remember: Bool) {
        calls.append("secret(\(title)|\(message)|\(remember ?? "-"))")
        if let error { throw error }
        return secretAnswer
    }

    func text(title: String, message: String, placeholder: String) throws -> String {
        calls.append("text(\(title)|\(message)|\(placeholder))")
        if let error { throw error }
        return textAnswer
    }

    var chain: [ProcessLink] = []

    func confirm(title: String, message: String, allow: String, deny: String, chain: [ProcessLink]) throws -> Bool {
        self.chain = chain
        calls.append("confirm(\(title)|\(message)|\(allow)|\(deny))")
        if let error { throw error }
        return confirmAnswer
    }

    func notify(title: String, message: String) throws {
        calls.append("notify(\(title)|\(message))")
        if let error { throw error }
    }
}

final class FakeStore: SecretStore, @unchecked Sendable {
    var items: [String: String] = [:]
    var error: Failure?

    func get(account: String) throws -> String {
        if let error { throw error }
        guard let v = items[account] else { throw Failure.notFound }
        return v
    }

    func set(account: String, secret: String) throws {
        if let error { throw error }
        items[account] = secret
    }

    func delete(account: String) throws {
        if let error { throw error }
        guard items.removeValue(forKey: account) != nil else { throw Failure.notFound }
    }
}

@MainActor
final class DispatcherTests: XCTestCase {
    // XCTest makes a new instance per test method, so these start fresh each time.
    let dialogs = FakeDialogs()
    let store = FakeStore()
    var dispatcher: Dispatcher { Dispatcher(dialogs: dialogs, store: store) }

    func testSecretWithCheckbox() {
        let resp = dispatcher.handle(Request(op: .secret, title: "T", message: "M", remember: .init(label: "Keep")))
        XCTAssertEqual(resp, .success(answer: "s3cret", remember: true))
        XCTAssertEqual(dialogs.calls, ["secret(T|M|Keep)"])
    }

    func testSecretWithoutCheckboxHasNoRememberField() {
        let resp = dispatcher.handle(Request(op: .secret, title: "T"))
        XCTAssertEqual(resp, .success(answer: "s3cret", remember: nil))
        XCTAssertEqual(dialogs.calls, ["secret(T||-)"])
    }

    func testCancelled() {
        dialogs.error = .cancelled
        XCTAssertEqual(dispatcher.handle(Request(op: .secret)), .failure(.cancelled))
        XCTAssertEqual(dispatcher.handle(Request(op: .text)), .failure(.cancelled))
    }

    func testText() {
        dialogs.textAnswer = "SHA256:abc"
        let resp = dispatcher.handle(Request(op: .text, title: "Host", message: "?", placeholder: "yes/no"))
        XCTAssertEqual(resp, .success(answer: "SHA256:abc"))
        XCTAssertEqual(dialogs.calls, ["text(Host|?|yes/no)"])
    }

    func testConfirm() {
        XCTAssertEqual(
            dispatcher.handle(Request(op: .confirm, title: "Allow?", allow: "Yes", deny: "No")),
            .success(answer: "yes"))
        dialogs.confirmAnswer = false
        XCTAssertEqual(dispatcher.handle(Request(op: .confirm, title: "Allow?")), .success(answer: "no"))
        XCTAssertEqual(dialogs.calls, ["confirm(Allow?||Yes|No)", "confirm(Allow?||Allow|Deny)"])
    }

    func testNotify() {
        XCTAssertEqual(dispatcher.handle(Request(op: .notify, title: "Touch", message: "the key")), .success())
        XCTAssertEqual(dialogs.calls, ["notify(Touch|the key)"])
    }

    func testKeychainRoundTrip() {
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainGet, account: "k")), .failure(.notFound))
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainSet, account: "k", secret: "v")), .success())
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainGet, account: "k")), .success(answer: "v"))
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainDelete, account: "k")), .success())
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainDelete, account: "k")), .failure(.notFound))
        XCTAssertTrue(dialogs.calls.isEmpty)
    }

    func testKeychainDenied() {
        store.error = .denied
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainGet, account: "k")), .failure(.denied))
    }

    func testKeychainValidation() {
        XCTAssertEqual(
            dispatcher.handle(Request(op: .keychainGet)).error, "keychain.get needs an account")
        XCTAssertEqual(
            dispatcher.handle(Request(op: .keychainSet, account: "k")).error, "keychain.set needs a secret")
        XCTAssertEqual(
            dispatcher.handle(Request(op: .keychainDelete, account: "")).error, "keychain.delete needs an account")
    }

    func testOtherErrorsTravelAsText() {
        store.error = .other("disk on fire")
        XCTAssertEqual(dispatcher.handle(Request(op: .keychainSet, account: "k", secret: "v")).error, "disk on fire")
    }
}
