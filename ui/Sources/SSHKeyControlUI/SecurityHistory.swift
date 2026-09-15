import AppKit
import Foundation

struct HistoryPolicy: Codable, Equatable, Sendable {
    var retentionDays = 7
    var maxEvents = 1000

    var validated: Self {
        Self(retentionDays: [1, 7, 30].contains(retentionDays) ? retentionDays : 7,
             maxEvents: [250, 1000, 5000].contains(maxEvents) ? maxEvents : 1000)
    }
}

struct SecurityEvent: Decodable, Identifiable, Sendable {
    let id: UInt64
    let time: Date
    let kind: String
    let outcome: String
    let source: String?
    let keyFingerprint: String?
    let hostFingerprint: String?
    let user: String?
    let scope: String?
    let expiresAt: Date?
    /// The program a timed decision was kept for, as it was at the time. The
    /// journal records what happened; it never brings a program back to life.
    let process: String?
    let processPid: Int32?

    /// What the detail pane reads for the program. A decision kept for nobody
    /// in particular says so, rather than leaving the field blank.
    var programLabel: String {
        guard let name = process, !name.isEmpty else { return L10n.string("Every program") }
        return processPid.map { "\(name) [\($0)]" } ?? name
    }
    var isVerified: Bool { !(hostFingerprint ?? "").isEmpty && !(user ?? "").isEmpty }
    var title: String {
        switch outcome {
        case "approved": L10n.string("Approved")
        case "denied": L10n.string("Denied")
        case "cancelled": L10n.string("Cancelled")
        case "revoked": L10n.string("Temporary decision revoked")
        case "updated": L10n.string("Temporary decision duration changed")
        case "started": L10n.string("Agent started")
        case "native_removed": L10n.string("Key removed from system agent")
        case "native_remove_failed": L10n.string("System agent key removal failed")
        case "native_unavailable": L10n.string("System agent monitoring failed")
        default: L10n.string("Error")
        }
    }
    var destination: String {
        if kind == "native_agent" { return L10n.string("System SSH agent") }
        if kind == "agent" { return L10n.string("SSH Key Control agent") }
        if !isVerified { return L10n.string("Unverified destination") }
        return "\(user ?? "") · \((hostFingerprint ?? "").prefix(22))…"
    }
}

struct HistoryDocument: Decodable, Sendable {
    let version: Int
    let events: [SecurityEvent]
}

enum HistoryFiles {
    static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/SSH Key Control", isDirectory: true)
    }
    static var policyURL: URL { directory.appendingPathComponent("history-settings.json") }
    static var historyURL: URL { directory.appendingPathComponent("history.json") }

    static func readPolicy(at url: URL = policyURL) -> HistoryPolicy {
        guard let data = try? boundedRead(url, limit: 8192),
              let policy = try? JSONDecoder().decode(HistoryPolicy.self, from: data) else { return HistoryPolicy() }
        return policy.validated
    }

    static func savePolicy(_ policy: HistoryPolicy, at url: URL = policyURL) throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let values = try dir.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        // Atomic writing preserves the old preferences if encoding or writing fails.
        let data = try JSONEncoder().encode(policy.validated)
        // umask is process-global: use a private temporary file instead.
        let temp = dir.appendingPathComponent(".settings-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: temp) }
        guard FileManager.default.createFile(atPath: temp.path, contents: data,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        if rename(temp.path, url.path) != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    static func boundedRead(_ url: URL, limit: Int) throws -> Data {
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey, .fileSizeKey])
        guard values.isSymbolicLink != true, values.isRegularFile == true, (values.fileSize ?? limit + 1) <= limit else {
            throw CocoaError(.fileReadCorruptFile)
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else { throw CocoaError(.fileReadTooLarge) }
        return data
    }

    static func load(at url: URL = historyURL, policy: HistoryPolicy = readPolicy()) throws -> [SecurityEvent] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let raw = try decoder.singleValueContainer().decode(String.self)
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: raw) { return date }
            formatter.formatOptions = [.withInternetDateTime]
            guard let date = formatter.date(from: raw) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid date"))
            }
            return date
        }
        let document = try decoder.decode(HistoryDocument.self, from: boundedRead(url, limit: 8 << 20))
        guard document.version == 1 else { throw CocoaError(.fileReadUnknown) }
        let cutoff = Date().addingTimeInterval(-Double(policy.validated.retentionDays) * 86400)
        return Array(document.events.filter { $0.time >= cutoff }.suffix(policy.validated.maxEvents).reversed())
    }
}

struct AgentStatus: Decodable, Sendable {
    let running: Bool
    let installed: Bool
    let pid: Int
}

@MainActor
final class SecurityHistoryModel: ObservableObject {
    @Published private(set) var events: [SecurityEvent] = []
    @Published private(set) var error: String?
    @Published private(set) var status: AgentStatus?
    @Published private(set) var refreshing = false

    func refresh() {
        guard !refreshing else { return }
        refreshing = true
        Task {
            let result = await Task.detached { () -> Result<[SecurityEvent], Error> in
                if !FileManager.default.fileExists(atPath: HistoryFiles.historyURL.path) { return .success([]) }
                return Result { try HistoryFiles.load() }
            }.value
            switch result {
            case .success(let events): self.events = events; error = nil
            case .failure: error = L10n.string("History could not be read. It may be damaged or inaccessible."); events = []
            }
            status = await Self.readStatus()
            refreshing = false
        }
    }

    nonisolated private static func readStatus() async -> AgentStatus? {
        guard let executable = Bundle.main.url(forAuxiliaryExecutable: "ssh-key-control") else { return nil }
        return await Task.detached {
            let process = Process()
            let output = Pipe()
            process.executableURL = executable
            process.arguments = ["status", "--json"]
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                let timer = DispatchSource.makeTimerSource()
                timer.schedule(deadline: .now() + 3)
                timer.setEventHandler { if process.isRunning { process.terminate() } }
                timer.resume()
                defer { timer.cancel() }
                process.waitUntilExit()
                guard process.terminationStatus == 0 else { return nil }
                return try JSONDecoder().decode(AgentStatus.self, from: output.fileHandleForReading.readDataToEndOfFile())
            } catch { return nil }
        }.value
    }
}
