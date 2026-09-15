import Foundation
import XCTest
@testable import SSHKeyControlUI

/// The agent and the key files on disk as the window sees them through the
/// command line: a list that answers what is loaded, and two commands that
/// change it.
@MainActor
private final class FakeAgent {
    struct Entry {
        var path: String
        var fingerprint: String
        var loaded = false
        var encrypted = true
        var comment = ""
    }

    var available = true
    var entries: [Entry]
    /// Key files that exist but are listed only when someone adds them by hand.
    var addable: [Entry] = []
    var operations: [AgentSetupOperation] = []
    /// What loading or unloading says when it will not work.
    var failure: String?

    init(_ entries: [Entry] = []) { self.entries = entries }

    func run(_ operation: AgentSetupOperation) -> AgentSetupResult {
        operations.append(operation)
        switch operation {
        case .listKeys(let extra):
            for path in extra {
                guard let found = addable.first(where: { $0.path == path }),
                      !entries.contains(where: { $0.path == path }) else { continue }
                entries.append(found)
            }
            return AgentSetupResult(succeeded: true, details: listing)
        case .loadKeys(let paths):
            if let failure { return AgentSetupResult(succeeded: false, details: failure) }
            for index in entries.indices where paths.isEmpty || paths.contains(entries[index].path) {
                entries[index].loaded = true
            }
            return AgentSetupResult(succeeded: true, details: "Identity added")
        case .unloadKeys(let fingerprints):
            if let failure { return AgentSetupResult(succeeded: false, details: failure) }
            for index in entries.indices where fingerprints.isEmpty || fingerprints.contains(entries[index].fingerprint) {
                entries[index].loaded = false
            }
            // A key with no file of its own is only in the list while the agent
            // holds it.
            entries.removeAll { $0.path.isEmpty && !$0.loaded }
            return AgentSetupResult(succeeded: true, details: "removed")
        default:
            return AgentSetupResult(succeeded: true, details: "")
        }
    }

    private var listing: String {
        let rows = entries.map {
            """
            {"fingerprint":"\($0.fingerprint)","algorithm":"ssh-ed25519","comment":"\($0.comment)",\
            "path":"\($0.path)","loaded":\($0.loaded),"encrypted":\($0.encrypted)}
            """
        }
        return #"{"available":\#(available),"keys":[\#(rows.joined(separator: ","))]}"#
    }
}

@MainActor
private final class FakeMemory: PassphraseMemory {
    var known: Set<String> = []
    var forgotten: [String] = []
    var refuses = false
    private struct Refused: Error {}

    func remembers(_ account: String) -> Bool { known.contains(account) }
    func forget(_ account: String) throws {
        if refuses { throw Refused() }
        forgotten.append(account)
        known.remove(account)
    }
}

@MainActor
final class KeyringTests: XCTestCase {
    private let bundle = URL(fileURLWithPath: "/Applications/SSH Key Control.app")
    private var scratch: UserDefaults?

    /// Settings of this test alone: a suite nobody else writes to, emptied when
    /// the test is over so the next one starts with a person who has chosen
    /// nothing yet.
    private var defaults: UserDefaults {
        if let scratch { return scratch }
        let suite = "io.github.alvnukov.ssh-key-control.tests." + UUID().uuidString
        let made = UserDefaults(suiteName: suite)!
        scratch = made
        addTeardownBlock { UserDefaults.standard.removePersistentDomain(forName: suite) }
        return made
    }

    private func model(_ agent: FakeAgent, memory: FakeMemory = FakeMemory()) -> KeyringModel {
        KeyringModel(run: { operation, _ in await MainActor.run { agent.run(operation) } },
                     memory: memory, preferences: KeyPreferences(defaults: defaults), bundle: bundle)
    }

    /// A key where this Mac keeps its own: the window shortens such a path with
    /// a tilde, which it can only do for the real home directory.
    private func personal(_ name: String, loaded: Bool = false, encrypted: Bool = true) -> FakeAgent.Entry {
        FakeAgent.Entry(path: sshDir + name, fingerprint: "SHA256:" + name,
                        loaded: loaded, encrypted: encrypted)
    }

    private var sshDir: String { NSHomeDirectory() + "/.ssh/" }

    func testTheMenuItemSaysHowManyKeysTheAgentHolds() async {
        let model = model(FakeAgent([personal("id_ed25519", loaded: true), personal("id_rsa")]))
        XCTAssertEqual(model.menuTitle, L10n.string("Keys…"))
        await model.refresh()
        XCTAssertEqual(model.menuTitle, L10n.format("Keys: %lld in agent…", 1))
        XCTAssertEqual(model.summary, L10n.format("Keys in agent: %lld", 1))
        XCTAssertTrue(model.canUnload)
    }

    // An agent that is not running is a different problem from an agent
    // holding nothing, and the menu must not spell one as the other.
    func testAnAgentThatIsNotRunningIsSaidOutrightRatherThanShownAsEmpty() async {
        let stopped = FakeAgent([personal("id_ed25519")])
        stopped.available = false
        let down = model(stopped)
        await down.refresh()
        XCTAssertEqual(down.menuTitle, L10n.string("Keys: agent not running…"))
        XCTAssertEqual(down.summary, L10n.string("SSH agent is not running"))
        XCTAssertFalse(down.canUnload)
        // The keys are still listed: they are what could be loaded once it is back.
        XCTAssertEqual(down.rows.count, 1)

        // An answer that is not a listing at all reads the same way: there is
        // nothing to show and nothing was loaded.
        for broken in ["not json at all", ""] {
            let silent = KeyringModel(run: { _, _ in AgentSetupResult(succeeded: true, details: broken) },
                                      memory: FakeMemory(), preferences: KeyPreferences(defaults: defaults), bundle: bundle)
            await silent.refresh()
            XCTAssertEqual(silent.summary, L10n.string("SSH agent is not running"), broken)
        }
        let empty = model(FakeAgent())
        await empty.refresh()
        XCTAssertEqual(empty.summary, L10n.format("Keys in agent: %lld", 0))
        XCTAssertFalse(empty.canUnload)
    }

    // The switch on a row is that key's place in the agent, so it moves one
    // key: loading every key when someone asked for one would ask for
    // passphrases nobody offered to type.
    func testTheSwitchLoadsAndUnloadsTheOneKeyItBelongsTo() async {
        let agent = FakeAgent([personal("id_ed25519"), personal("id_rsa")])
        let model = model(agent)
        await model.refresh()
        let first = model.rows[0]
        await model.setLoaded(first, true)
        XCTAssertEqual(agent.operations.dropLast(), [.listKeys([]), .loadKeys([sshDir + "id_ed25519"])])
        XCTAssertTrue(model.rows[0].loaded)
        XCTAssertFalse(model.rows[1].loaded)
        XCTAssertEqual(model.menuTitle, L10n.format("Keys: %lld in agent…", 1))
        await model.setLoaded(model.rows[0], false)
        XCTAssertEqual(agent.operations.last, .listKeys([]))
        XCTAssertTrue(agent.operations.contains(.unloadKeys(["SHA256:id_ed25519"])))
        XCTAssertFalse(model.rows[0].loaded)
        // Asking for the state a key is already in does nothing at all.
        let quiet = agent.operations.count
        await model.setLoaded(model.rows[0], false)
        XCTAssertEqual(agent.operations.count, quiet)
    }

    func testEveryKeyIsListedWhetherOrNotTheAgentHoldsIt() async {
        let agent = FakeAgent([personal("id_ed25519", loaded: true, encrypted: false),
                               FakeAgent.Entry(path: "", fingerprint: "SHA256:token", loaded: true, comment: "yubikey")])
        let model = model(agent)
        await model.refresh()
        XCTAssertEqual(model.rows.map(\.name), ["id_ed25519", "yubikey"])
        XCTAssertEqual(model.rows[0].detail, "~/.ssh/id_ed25519")
        // A key the agent was given by something else can be taken out here,
        // but there is no file to put it back from.
        let orphan = model.rows[1]
        XCTAssertFalse(orphan.canLoad)
        XCTAssertTrue(orphan.canUnload)
        XCTAssertEqual(orphan.detail, L10n.string("Loaded by something else; no key file on this Mac"))
        await model.setLoaded(orphan, false)
        XCTAssertEqual(model.rows.map(\.name), ["id_ed25519"])
    }

    func testAFailedLoadIsReportedAndTheKeyStaysAsTheAgentHasIt() async {
        let agent = FakeAgent([personal("id_rsa")])
        agent.failure = "Bad passphrase, try again"
        let model = model(agent)
        await model.refresh()
        await model.setLoaded(model.rows[0], true)
        XCTAssertFalse(model.rows[0].loaded)
        let failure = try? XCTUnwrap(model.failure)
        XCTAssertEqual(failure?.hasPrefix(L10n.string("Could not load keys into the agent")), true)
        XCTAssertEqual(failure?.contains("Bad passphrase"), true)
        // A load that works afterwards clears what the failed one said.
        agent.failure = nil
        await model.setLoaded(model.rows[0], true)
        XCTAssertNil(model.failure)
        XCTAssertTrue(model.rows[0].loaded)
    }

    func testWhatIsLoadedAtLoginIsRememberedPerKey() async {
        let agent = FakeAgent([personal("id_ed25519"), personal("id_rsa")])
        let model = model(agent)
        await model.refresh()
        XCTAssertFalse(model.rows[0].loadsAtLogin)
        model.setLoadsAtLogin(model.rows[0], true)
        XCTAssertTrue(model.rows[0].loadsAtLogin)
        XCTAssertFalse(model.rows[1].loadsAtLogin)
        XCTAssertEqual(defaults.stringArray(forKey: KeyPreferences.loginKey), [sshDir + "id_ed25519"])
        model.setLoadsAtLogin(model.rows[0], false)
        XCTAssertEqual(defaults.stringArray(forKey: KeyPreferences.loginKey), [])
    }

    // Loading at login with no remembered passphrase means typing one at every
    // login. It is allowed, and it is said out loud.
    func testAKeyThatWillAskAtEveryLoginSaysSo() async {
        let memory = FakeMemory()
        let agent = FakeAgent([personal("id_ed25519"), personal("id_rsa"), personal("plain", encrypted: false)])
        memory.known = [sshDir + "id_rsa"]
        let model = model(agent, memory: memory)
        await model.refresh()
        for row in model.rows { model.setLoadsAtLogin(row, true) }
        XCTAssertTrue(model.rows[0].asksAtEveryLogin)
        // A remembered passphrase is read once by macOS, not typed.
        XCTAssertTrue(model.rows[1].remembered)
        XCTAssertFalse(model.rows[1].asksAtEveryLogin)
        // A key with no passphrase asks for nothing in the first place.
        XCTAssertFalse(model.rows[2].asksAtEveryLogin)
        // Nothing here asked the keychain for a secret.
        XCTAssertTrue(memory.forgotten.isEmpty)
    }

    func testForgettingAPasswordLeavesTheKeyWhereItIs() async {
        let memory = FakeMemory()
        memory.known = [sshDir + "id_rsa"]
        let agent = FakeAgent([personal("id_rsa", loaded: true)])
        let model = model(agent, memory: memory)
        await model.refresh()
        XCTAssertTrue(model.rows[0].remembered)
        model.forgetPassword(model.rows[0])
        XCTAssertEqual(memory.forgotten, [sshDir + "id_rsa"])
        XCTAssertFalse(model.rows[0].remembered)
        XCTAssertTrue(model.rows[0].loaded)
        XCTAssertNil(model.failure)
        memory.known = [sshDir + "id_rsa"]
        memory.refuses = true
        await model.refresh()
        model.forgetPassword(model.rows[0])
        XCTAssertEqual(model.failure, L10n.string("Could not forget the saved password"))
    }

    func testAKeyAddedByHandIsListedAndCanBeTakenOffTheListAgain() async {
        let agent = FakeAgent([personal("id_ed25519")])
        agent.addable = [FakeAgent.Entry(path: "/Volumes/work/deploy", fingerprint: "SHA256:deploy")]
        let model = model(agent)
        await model.refresh()
        await model.add(keyFile: URL(fileURLWithPath: "/Volumes/work/deploy"))
        XCTAssertEqual(model.rows.map(\.name), ["id_ed25519", "deploy"])
        XCTAssertTrue(model.rows[1].addedByHand)
        XCTAssertFalse(model.rows[0].addedByHand)
        XCTAssertEqual(agent.operations.last, .listKeys(["/Volumes/work/deploy"]))
        model.setLoadsAtLogin(model.rows[1], true)
        await model.removeFromList(model.rows[1])
        XCTAssertEqual(defaults.stringArray(forKey: KeyPreferences.addedKey), [])
        // Its place in the login list goes with it; a key that is not listed
        // cannot be loaded at login behind the person's back.
        XCTAssertEqual(defaults.stringArray(forKey: KeyPreferences.loginKey), [])
    }

    func testAFileThatIsNotAKeyIsNotKeptOnTheList() async {
        let model = model(FakeAgent([personal("id_ed25519")]))
        await model.refresh()
        await model.add(keyFile: URL(fileURLWithPath: sshDir + "known_hosts"))
        XCTAssertEqual(model.rows.count, 1)
        XCTAssertEqual(model.failure, L10n.format("%@ is not a private key file", "known_hosts"))
        XCTAssertEqual(defaults.stringArray(forKey: KeyPreferences.addedKey), [])
    }

    // Loading at login is a convenience, not a decision to overrule: an agent
    // that already holds keys was set up by whoever put them there.
    func testKeysMarkedForLoginGoInOnlyWhileTheAgentIsEmpty() async {
        let agent = FakeAgent([personal("id_ed25519"), personal("id_rsa")])
        let model = model(agent)
        await model.refresh()
        model.setLoadsAtLogin(model.rows[0], true)

        await model.loadAtLogin()
        XCTAssertTrue(model.rows[0].loaded)
        XCTAssertFalse(model.rows[1].loaded)
        XCTAssertTrue(agent.operations.contains(.loadKeys([sshDir + "id_ed25519"])))

        // With something already in the agent, login loading stays out of it.
        await model.setLoaded(model.rows[0], false)
        await model.setLoaded(model.rows[1], true)
        let quiet = agent.operations.count
        await model.loadAtLogin()
        XCTAssertFalse(agent.operations.dropFirst(quiet).contains { if case .loadKeys = $0 { return true } else { return false } })
        XCTAssertFalse(model.rows[0].loaded)
    }

    func testNothingIsAskedOfTheAgentWhenNoKeyIsMarkedForLogin() async {
        let agent = FakeAgent([personal("id_ed25519")])
        let model = model(agent)
        await model.loadAtLogin()
        XCTAssertEqual(agent.operations, [])
    }

    func testUnloadingEverythingTakesOutEveryKeyAtOnce() async {
        let agent = FakeAgent([personal("id_ed25519", loaded: true), personal("id_rsa", loaded: true)])
        let model = model(agent)
        await model.refresh()
        await model.unloadAll()
        XCTAssertTrue(agent.operations.contains(.unloadKeys([])))
        XCTAssertEqual(model.rows.filter(\.loaded).count, 0)
        XCTAssertFalse(model.canUnload)
    }

    // Pressing a second switch while a passphrase dialog is up would put a
    // second dialog behind the first, asking for another key at the same time.
    func testASecondChangeIsIgnoredWhileOneIsStillRunning() async {
        var calls = 0
        let started = expectation(description: "load started")
        let release = expectation(description: "load may finish")
        let listing = #"{"available":true,"keys":[{"fingerprint":"SHA256:a","algorithm":"ssh-ed25519","comment":"","path":"/Users/me/.ssh/id_ed25519","loaded":false,"encrypted":true}]}"#
        let model = KeyringModel(run: { operation, _ in
            guard case .loadKeys = operation else {
                return AgentSetupResult(succeeded: true, details: listing)
            }
            await MainActor.run { calls += 1 }
            started.fulfill()
            await self.fulfillment(of: [release], timeout: 2)
            return AgentSetupResult(succeeded: true, details: "Identity added")
        }, memory: FakeMemory(), preferences: KeyPreferences(defaults: defaults), bundle: bundle)
        await model.refresh()
        let row = model.rows[0]
        let first = Task { await model.setLoaded(row, true) }
        await fulfillment(of: [started], timeout: 2)
        XCTAssertTrue(model.busy)
        await model.setLoaded(row, true)
        release.fulfill()
        await first.value
        XCTAssertEqual(calls, 1)
        XCTAssertFalse(model.busy)
    }

    // Loading a key waits for a person to type a passphrase into a dialog,
    // which is not something to interrupt after half a minute.
    func testTypingAPassphraseIsNotRacingTheKillTimer() {
        XCTAssertGreaterThanOrEqual(AgentSetupOperation.loadKeys([]).timeout, 300)
        for quick in [AgentSetupOperation.unloadKeys([]), .listKeys([]), .enable, .repair] {
            XCTAssertEqual(quick.timeout, 30, "\(quick)")
        }
    }

    func testTheCommandsTheWindowRunsAreTheOnesTheAgentUnderstands() {
        XCTAssertEqual(AgentSetupOperation.loadKeys([]).arguments, ["keys", "load"])
        XCTAssertEqual(AgentSetupOperation.loadKeys(["/k/one", "/k/two"]).arguments, ["keys", "load", "/k/one", "/k/two"])
        XCTAssertEqual(AgentSetupOperation.unloadKeys([]).arguments, ["keys", "unload"])
        XCTAssertEqual(AgentSetupOperation.unloadKeys(["SHA256:one"]).arguments, ["keys", "unload", "SHA256:one"])
        XCTAssertEqual(AgentSetupOperation.listKeys([]).arguments, ["keys", "list", "--json"])
        XCTAssertEqual(AgentSetupOperation.listKeys(["/k/one"]).arguments, ["keys", "list", "--json", "/k/one"])
    }
}
