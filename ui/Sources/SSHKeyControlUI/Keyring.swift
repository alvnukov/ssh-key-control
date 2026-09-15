import Foundation

/// What the agent holds and what this Mac could give it. Only public halves,
/// comments and paths are in here: the agent has no operation that gives a key
/// back, which is the point of it.
struct KeyringListing: Decodable, Equatable, Sendable {
    struct Key: Decodable, Equatable, Sendable {
        let fingerprint: String
        let algorithm: String
        let comment: String
        /// The key file this row can be loaded from. Empty means the agent
        /// holds a key whose file is not one this Mac knows about.
        let path: String
        let loaded: Bool
        /// Whether loading this key asks for a passphrase, which is what
        /// decides whether it can be loaded with nobody at the keyboard.
        let encrypted: Bool
    }
    let available: Bool
    let keys: [Key]
}

/// One line of the key window: a key, and everything a person decides about it.
struct KeyRow: Identifiable, Equatable {
    let fingerprint: String
    let algorithm: String
    let comment: String
    let path: String
    let loaded: Bool
    let encrypted: Bool
    /// Whether the passphrase for this key is in the keychain already.
    let remembered: Bool
    let loadsAtLogin: Bool
    /// Whether this key is listed because someone pointed at it by hand.
    let addedByHand: Bool

    var id: String { path.isEmpty ? fingerprint : path }
    /// A key file that is not there any more cannot be loaded from.
    var canLoad: Bool { !path.isEmpty }
    var canUnload: Bool { loaded && !fingerprint.isEmpty }

    var name: String {
        if !path.isEmpty { return (path as NSString).lastPathComponent }
        return comment.isEmpty ? fingerprint : comment
    }

    var detail: String {
        guard !path.isEmpty else { return L10n.string("Loaded by something else; no key file on this Mac") }
        let shown = (path as NSString).abbreviatingWithTildeInPath
        guard !comment.isEmpty, comment != path, comment != name else { return shown }
        return shown + " — " + comment
    }

    /// A key that is loaded at login and has no remembered passphrase asks for
    /// one every single login. That is a choice a person may make, but not one
    /// they should make without being told.
    var asksAtEveryLogin: Bool { loadsAtLogin && encrypted && !remembered }
}

/// Where the choices about keys are kept: which ones to put into the agent at
/// login, and which key files were added by hand. Both are lists of paths, in
/// the same preferences as the rest of this app's settings.
@MainActor
struct KeyPreferences {
    static let loginKey = "loadKeysAtLogin"
    static let addedKey = "addedKeyFiles"
    private let defaults: UserDefaults

    init(defaults: UserDefaults? = nil) {
        if let defaults {
            self.defaults = defaults
        } else {
            self.defaults = UserDefaults(suiteName: AppKitDialogs.defaultsSuite) ?? .standard
        }
    }

    var atLogin: [String] {
        get { defaults.stringArray(forKey: Self.loginKey) ?? [] }
        nonmutating set { defaults.set(newValue, forKey: Self.loginKey) }
    }

    var added: [String] {
        get { defaults.stringArray(forKey: Self.addedKey) ?? [] }
        nonmutating set { defaults.set(newValue, forKey: Self.addedKey) }
    }
}

/// What the window may ask the keychain. Whether a passphrase is remembered is
/// answered from the keychain's index and puts no prompt on screen; reading the
/// secret itself is the helper's business and always asks.
@MainActor
protocol PassphraseMemory {
    func remembers(_ account: String) -> Bool
    func forget(_ account: String) throws
}

struct KeychainMemory: PassphraseMemory {
    private let keychain = Keychain()
    func remembers(_ account: String) -> Bool { keychain.remembers(account: account) }
    func forget(_ account: String) throws { try keychain.delete(account: account) }
}

/// KeyringModel is the key window and the menu behind it: which keys exist,
/// which of them the agent holds, and what a person can do about that. Without
/// it the only way to put a key into the agent is to know that `ssh-add` exists
/// and that this agent is the one it talks to.
@MainActor
final class KeyringModel: ObservableObject {
    @Published private(set) var listing: KeyringListing?
    @Published private(set) var busy = false
    /// What went wrong the last time something was asked of the agent. The
    /// toggles show the agent's own answer, so a failure needs saying in words.
    @Published private(set) var failure: String?
    @Published private(set) var remembered: Set<String> = []
    private let run: (AgentSetupOperation, URL) async -> AgentSetupResult
    private let memory: PassphraseMemory
    private let preferences: KeyPreferences
    private let bundle: URL

    init(run: @escaping (AgentSetupOperation, URL) async -> AgentSetupResult = {
            await AgentSetupCommand.run($0, bundle: $1)
         },
         memory: PassphraseMemory = KeychainMemory(),
         preferences: KeyPreferences = KeyPreferences(),
         bundle: URL = Bundle.main.bundleURL) {
        self.run = run
        self.memory = memory
        self.preferences = preferences
        self.bundle = bundle
    }

    /// The menu item that opens the window says what the agent holds, so the
    /// count is read without opening anything.
    var menuTitle: String {
        guard let listing else { return L10n.string("Keys…") }
        guard listing.available else { return L10n.string("Keys: agent not running…") }
        return L10n.format("Keys: %lld in agent…", listing.keys.filter(\.loaded).count)
    }

    /// The line at the top of the window. An agent that is not running is said
    /// outright: "no keys" would be a different problem with a different answer.
    var summary: String {
        guard let listing else { return L10n.string("Checking the agent…") }
        guard listing.available else { return L10n.string("SSH agent is not running") }
        return L10n.format("Keys in agent: %lld", listing.keys.filter(\.loaded).count)
    }

    var canUnload: Bool { listing?.keys.contains(where: \.loaded) ?? false }

    var rows: [KeyRow] {
        let atLogin = Set(preferences.atLogin)
        let added = Set(preferences.added)
        return (listing?.keys ?? []).map { key in
            KeyRow(fingerprint: key.fingerprint, algorithm: key.algorithm, comment: key.comment,
                   path: key.path, loaded: key.loaded, encrypted: key.encrypted,
                   remembered: remembered.contains(key.path),
                   loadsAtLogin: atLogin.contains(key.path),
                   addedByHand: added.contains(key.path))
        }
    }

    func refresh() async {
        let result = await run(.listKeys(preferences.added), bundle)
        guard result.succeeded,
              let data = result.details.data(using: .utf8),
              let listing = try? JSONDecoder().decode(KeyringListing.self, from: data) else {
            self.listing = KeyringListing(available: false, keys: [])
            return
        }
        self.listing = listing
        // One attributes-only lookup per key. None of them prompts, which is
        // what makes a column of these possible at all.
        remembered = Set(listing.keys.map(\.path).filter { !$0.isEmpty && memory.remembers($0) })
    }

    /// The switch on a row is the key's place in the agent: turning it on loads
    /// that key and turning it off takes it out again. There is nothing to
    /// apply afterwards, and nothing to undo.
    func setLoaded(_ row: KeyRow, _ wanted: Bool) async {
        guard wanted != row.loaded else { return }
        if wanted {
            guard row.canLoad else { return }
            await perform(.loadKeys([row.path]), failure: L10n.string("Could not load keys into the agent"))
        } else {
            guard row.canUnload else { return }
            await perform(.unloadKeys([row.fingerprint]), failure: L10n.string("Could not unload the keys"))
        }
    }

    func unloadAll() async {
        await perform(.unloadKeys([]), failure: L10n.string("Could not unload the keys"))
    }

    func setLoadsAtLogin(_ row: KeyRow, _ wanted: Bool) {
        guard !row.path.isEmpty else { return }
        var paths = preferences.atLogin.filter { $0 != row.path }
        if wanted { paths.append(row.path) }
        preferences.atLogin = paths
        objectWillChange.send()
    }

    /// Forgetting a passphrase leaves the key where it is: the agent already
    /// holds what it holds, and this only decides what the next load will ask.
    func forgetPassword(_ row: KeyRow) {
        guard row.remembered else { return }
        do {
            try memory.forget(row.path)
            remembered.remove(row.path)
            failure = nil
        } catch {
            failure = L10n.string("Could not forget the saved password")
        }
    }

    func add(keyFile url: URL) async {
        let path = url.standardizedFileURL.path
        guard !preferences.added.contains(path) else { return }
        preferences.added = preferences.added + [path]
        await refresh()
        // A file that is not a private key is not listed, and saying nothing
        // about it would leave the person waiting for a row that never comes.
        if !(listing?.keys.contains(where: { $0.path == path }) ?? false) {
            preferences.added = preferences.added.filter { $0 != path }
            failure = L10n.format("%@ is not a private key file", (path as NSString).lastPathComponent)
        }
    }

    /// Only keys that were added by hand can be taken off the list; the ones in
    /// ~/.ssh and in the SSH config are there because this Mac has them.
    func removeFromList(_ row: KeyRow) async {
        guard row.addedByHand else { return }
        preferences.added = preferences.added.filter { $0 != row.path }
        preferences.atLogin = preferences.atLogin.filter { $0 != row.path }
        await refresh()
    }

    /// The keys marked "load at login", put into the agent when the menu bar
    /// app starts. Only into an agent that holds nothing: an agent with keys in
    /// it was set up by whoever put them there, and asking for passphrases over
    /// that would be a surprise rather than a convenience.
    func loadAtLogin() async {
        let wanted = preferences.atLogin
        guard !wanted.isEmpty else { return }
        await refresh()
        guard let listing, listing.available, !listing.keys.contains(where: \.loaded) else { return }
        await perform(.loadKeys(wanted), failure: L10n.string("Could not load keys into the agent"))
    }

    /// Two loads at once would ask for the same passphrase twice, so a second
    /// press while one is running does nothing rather than queueing a dialog
    /// behind the one already on screen.
    @discardableResult
    private func perform(_ operation: AgentSetupOperation, failure message: String) async -> AgentSetupResult? {
        guard !busy else { return nil }
        busy = true
        defer { busy = false }
        let result = await run(operation, bundle)
        failure = result.succeeded ? nil : message + "\n" + result.details.trimmingCharacters(in: .whitespacesAndNewlines)
        await refresh()
        return result
    }
}
